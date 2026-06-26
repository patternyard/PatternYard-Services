use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use mongodb::Collection;
use mongodb::bson::{Bson, Document, doc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

#[derive(Default)]
struct Stats {
    source: u64,
    migrated: u64,
    rejected: u64,
    checksum: Sha256,
}

pub async fn migrate(
    source: Collection<Document>,
    target: Option<&PgPool>,
    limit: Option<u64>,
) -> Result<()> {
    let mut query = source.find(doc! {}).sort(doc! { "_id": 1 });
    if let Some(limit) = limit {
        query = query.limit(limit as i64);
    }
    let mut cursor = query.await.context("read projects")?;
    let mut stats = Stats::default();

    while let Some(document) = cursor.try_next().await.context("advance projects cursor")? {
        stats.source += 1;
        let source_id_hash = safe_source_hash(&document);
        stats.checksum.update(source_id_hash.as_bytes());

        match ProjectRecord::from_document(&document) {
            Ok(project) => {
                if let Some(pool) = target
                    && upsert_project(pool, &project).await.is_err()
                {
                    stats.rejected += 1;
                    record_rejection(pool, &source_id_hash, "target-write").await?;
                    eprintln!(
                        "rejected projects record {source_id_hash}: target database rejected record"
                    );
                    continue;
                }
                stats.migrated += 1;
            }
            Err(message) => {
                stats.rejected += 1;
                if let Some(pool) = target {
                    record_rejection(pool, &source_id_hash, "source-shape").await?;
                }
                eprintln!("rejected projects record {source_id_hash}: {message}");
            }
        }
    }

    // Project-to-project references are applied only after every project row exists.
    if let Some(pool) = target {
        apply_remix_relationships(source.clone(), pool, limit).await?;
    }

    let checksum = hex::encode(stats.checksum.clone().finalize());
    if let Some(pool) = target {
        write_checkpoint(pool, &stats, &checksum).await?;
    }
    println!(
        "projects: source={} migrated={} rejected={} checksum={} mode={}",
        stats.source,
        stats.migrated,
        stats.rejected,
        checksum,
        if target.is_some() { "write" } else { "dry-run" }
    );

    if stats.rejected > 0 {
        bail!("projects migration completed with rejected records")
    }
    Ok(())
}

#[derive(Debug)]
struct ProjectRecord {
    id: String,
    author_id: String,
    title: String,
    instructions: String,
    notes: String,
    remix_of_id: Option<String>,
    featured: bool,
    views: i64,
    loves: i64,
    votes: i64,
    impressions: i64,
    rating: String,
    is_public: bool,
    soft_rejected: bool,
    hard_rejected: bool,
    hard_rejected_at: Option<DateTime<Utc>>,
    no_feature: bool,
    moderation_message: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl ProjectRecord {
    fn from_document(document: &Document) -> std::result::Result<Self, String> {
        let id = required_string(document, "id")?;
        let author_id = required_string(document, "author")?;
        let created_at = timestamp(document, "date").ok_or("missing date")?;
        let updated_at = timestamp(document, "lastUpdate").unwrap_or(created_at);
        let remix_of_id = optional_string(document, "remix")
            .filter(|value| !value.is_empty() && value != "0" && value != &id);

        Ok(Self {
            id,
            author_id,
            title: optional_string(document, "title").unwrap_or_default(),
            instructions: optional_string(document, "instructions").unwrap_or_default(),
            notes: optional_string(document, "notes").unwrap_or_default(),
            remix_of_id,
            featured: boolean(document, "featured"),
            views: nonnegative_i64(document, "views"),
            loves: nonnegative_i64(document, "loves"),
            votes: nonnegative_i64(document, "votes"),
            impressions: nonnegative_i64(document, "impressions"),
            rating: optional_string(document, "rating").unwrap_or_default(),
            is_public: document
                .get("public")
                .is_none_or(|_| boolean(document, "public")),
            soft_rejected: boolean(document, "softRejected"),
            hard_rejected: boolean(document, "hardReject"),
            hard_rejected_at: timestamp(document, "hardRejectTime"),
            no_feature: boolean(document, "noFeature"),
            moderation_message: optional_string(document, "moderationMessage"),
            created_at,
            updated_at,
        })
    }
}

async fn upsert_project(pool: &PgPool, project: &ProjectRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO app.projects
            (id, author_id, title, instructions, notes, remix_of_id, featured, views, loves,
             votes, impressions, rating, is_public, soft_rejected, hard_rejected,
             hard_rejected_at, no_feature, moderation_message, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                 $15, $16, $17, $18, $19)
         ON CONFLICT (id) DO UPDATE SET
            author_id = EXCLUDED.author_id,
            title = EXCLUDED.title,
            instructions = EXCLUDED.instructions,
            notes = EXCLUDED.notes,
            featured = EXCLUDED.featured,
            views = EXCLUDED.views,
            loves = EXCLUDED.loves,
            votes = EXCLUDED.votes,
            impressions = EXCLUDED.impressions,
            rating = EXCLUDED.rating,
            is_public = EXCLUDED.is_public,
            soft_rejected = EXCLUDED.soft_rejected,
            hard_rejected = EXCLUDED.hard_rejected,
            hard_rejected_at = EXCLUDED.hard_rejected_at,
            no_feature = EXCLUDED.no_feature,
            moderation_message = EXCLUDED.moderation_message,
            created_at = EXCLUDED.created_at,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(&project.id)
    .bind(&project.author_id)
    .bind(&project.title)
    .bind(&project.instructions)
    .bind(&project.notes)
    .bind(project.featured)
    .bind(project.views)
    .bind(project.loves)
    .bind(project.votes)
    .bind(project.impressions)
    .bind(&project.rating)
    .bind(project.is_public)
    .bind(project.soft_rejected)
    .bind(project.hard_rejected)
    .bind(project.hard_rejected_at)
    .bind(project.no_feature)
    .bind(&project.moderation_message)
    .bind(project.created_at)
    .bind(project.updated_at)
    .execute(pool)
    .await?;
    Ok(())
}

async fn apply_remix_relationships(
    source: Collection<Document>,
    pool: &PgPool,
    limit: Option<u64>,
) -> Result<()> {
    let mut query = source.find(doc! {}).sort(doc! { "_id": 1 });
    if let Some(limit) = limit {
        query = query.limit(limit as i64);
    }
    let mut cursor = query.await.context("read project remix relationships")?;
    while let Some(document) = cursor
        .try_next()
        .await
        .context("advance project remix cursor")?
    {
        let Ok(project) = ProjectRecord::from_document(&document) else {
            continue;
        };
        let Some(remix_of_id) = project.remix_of_id else {
            continue;
        };
        sqlx::query(
            "UPDATE app.projects child
             SET remix_of_id = parent.id
             FROM app.projects parent
             WHERE child.id = $1 AND parent.id = $2",
        )
        .bind(project.id)
        .bind(remix_of_id)
        .execute(pool)
        .await
        .context("apply project remix relationship")?;
    }
    Ok(())
}

async fn write_checkpoint(pool: &PgPool, stats: &Stats, checksum: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO migration.checkpoints
            (collection, source_count, migrated_count, rejected_count, checksum, completed_at)
         VALUES ('projects', $1, $2, $3, $4, now())
         ON CONFLICT (collection) DO UPDATE SET
            source_count = EXCLUDED.source_count,
            migrated_count = EXCLUDED.migrated_count,
            rejected_count = EXCLUDED.rejected_count,
            checksum = EXCLUDED.checksum,
            updated_at = now(),
            completed_at = EXCLUDED.completed_at",
    )
    .bind(stats.source as i64)
    .bind(stats.migrated as i64)
    .bind(stats.rejected as i64)
    .bind(checksum)
    .execute(pool)
    .await
    .context("write projects checkpoint")?;
    Ok(())
}

async fn record_rejection(pool: &PgPool, source_id_hash: &str, reason_code: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO migration.rejections (collection, source_id_hash, reason_code)
         VALUES ('projects', $1, $2)",
    )
    .bind(source_id_hash)
    .bind(reason_code)
    .execute(pool)
    .await
    .context("record safe projects migration rejection")?;
    Ok(())
}

fn required_string(document: &Document, key: &str) -> std::result::Result<String, String> {
    optional_string(document, key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing {key}"))
}

fn optional_string(document: &Document, key: &str) -> Option<String> {
    match document.get(key)? {
        Bson::String(value) => Some(value.clone()),
        Bson::Int32(value) => Some(value.to_string()),
        Bson::Int64(value) => Some(value.to_string()),
        Bson::Double(value) if value.is_finite() => Some(value.to_string()),
        _ => None,
    }
}

fn boolean(document: &Document, key: &str) -> bool {
    match document.get(key) {
        Some(Bson::Boolean(value)) => *value,
        Some(Bson::Int32(value)) => *value != 0,
        Some(Bson::Int64(value)) => *value != 0,
        _ => false,
    }
}

fn nonnegative_i64(document: &Document, key: &str) -> i64 {
    let value = match document.get(key) {
        Some(Bson::Int32(value)) => i64::from(*value),
        Some(Bson::Int64(value)) => *value,
        Some(Bson::Double(value)) if value.is_finite() => *value as i64,
        _ => 0,
    };
    value.max(0)
}

fn timestamp(document: &Document, key: &str) -> Option<DateTime<Utc>> {
    let millis = match document.get(key)? {
        Bson::DateTime(value) => value.timestamp_millis(),
        Bson::Int32(value) => i64::from(*value),
        Bson::Int64(value) => *value,
        Bson::Double(value) if value.is_finite() => *value as i64,
        Bson::String(value) => return value.parse::<DateTime<Utc>>().ok(),
        _ => return None,
    };
    (millis > 0)
        .then(|| DateTime::from_timestamp_millis(millis))
        .flatten()
}

fn safe_source_hash(document: &Document) -> String {
    let source = document
        .get("_id")
        .map(Bson::to_string)
        .unwrap_or_else(|| "missing-id".to_owned());
    hex::encode(Sha256::digest(source.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_project_metadata() {
        let project = ProjectRecord::from_document(&doc! {
            "id": "0000000042",
            "author": "01USER",
            "title": "Building Lab",
            "date": 1_700_000_000_000_i64,
            "lastUpdate": 1_700_000_001_000_i64,
            "remix": "0000000001",
            "views": 4,
            "loves": 2,
            "public": true
        })
        .unwrap();
        assert_eq!(project.id, "0000000042");
        assert_eq!(project.remix_of_id.as_deref(), Some("0000000001"));
        assert_eq!(project.views, 4);
        assert!(project.is_public);
    }

    #[test]
    fn rejects_projects_without_identity_or_author() {
        assert!(
            ProjectRecord::from_document(&doc! { "id": "42", "date": 1_700_000_000_000_i64 })
                .is_err()
        );
    }
}
