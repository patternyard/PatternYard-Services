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
    let mut cursor = query.await.context("read projectStats")?;
    let mut stats = Stats::default();

    while let Some(document) = cursor
        .try_next()
        .await
        .context("advance projectStats cursor")?
    {
        stats.source += 1;
        let source_id_hash = safe_source_hash(&document);
        stats.checksum.update(source_id_hash.as_bytes());

        match Interaction::from_document(&document) {
            Ok(interaction) => {
                if let Some(pool) = target
                    && let Err(error) = upsert_interaction(pool, &interaction).await
                {
                    stats.rejected += 1;
                    let reason = if foreign_key_violation(&error) {
                        "missing-relationship"
                    } else {
                        "target-write"
                    };
                    record_rejection(pool, &source_id_hash, reason).await?;
                    eprintln!(
                        "rejected projectStats record {source_id_hash}: {}",
                        if reason == "missing-relationship" {
                            "referenced account or project is missing"
                        } else {
                            "target database rejected record"
                        }
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
                eprintln!("rejected projectStats record {source_id_hash}: {message}");
            }
        }
    }

    let checksum = hex::encode(stats.checksum.clone().finalize());
    if let Some(pool) = target {
        write_checkpoint(pool, &stats, &checksum).await?;
    }
    println!(
        "projectStats: source={} migrated={} rejected={} checksum={} mode={}",
        stats.source,
        stats.migrated,
        stats.rejected,
        checksum,
        if target.is_some() { "write" } else { "dry-run" }
    );

    if stats.rejected > 0 {
        bail!("projectStats migration completed with rejected records")
    }
    Ok(())
}

#[derive(Debug)]
struct Interaction {
    project_id: String,
    user_id: String,
    kind: String,
    created_at: Option<DateTime<Utc>>,
}

impl Interaction {
    fn from_document(document: &Document) -> std::result::Result<Self, String> {
        let kind = required_string(document, "type")?;
        if !matches!(kind.as_str(), "love" | "vote") {
            return Err("unsupported project interaction type".to_owned());
        }

        Ok(Self {
            project_id: required_string(document, "projectId")?,
            user_id: required_string(document, "userId")?,
            kind,
            created_at: source_timestamp(document),
        })
    }
}

async fn upsert_interaction(pool: &PgPool, interaction: &Interaction) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO app.project_interactions (project_id, user_id, kind, created_at)
         VALUES ($1, $2, $3, COALESCE($4, now()))
         ON CONFLICT (project_id, user_id, kind) DO NOTHING",
    )
    .bind(&interaction.project_id)
    .bind(&interaction.user_id)
    .bind(&interaction.kind)
    .bind(interaction.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

async fn write_checkpoint(pool: &PgPool, stats: &Stats, checksum: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO migration.checkpoints
            (collection, source_count, migrated_count, rejected_count, checksum, completed_at)
         VALUES ('projectStats', $1, $2, $3, $4, now())
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
    .context("write projectStats checkpoint")?;
    Ok(())
}

async fn record_rejection(pool: &PgPool, source_id_hash: &str, reason_code: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO migration.rejections (collection, source_id_hash, reason_code)
         VALUES ('projectStats', $1, $2)",
    )
    .bind(source_id_hash)
    .bind(reason_code)
    .execute(pool)
    .await
    .context("record safe projectStats migration rejection")?;
    Ok(())
}

fn foreign_key_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database) if database.code().as_deref() == Some("23503")
    )
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

fn source_timestamp(document: &Document) -> Option<DateTime<Utc>> {
    match document.get("_id") {
        Some(Bson::ObjectId(value)) => {
            DateTime::from_timestamp_millis(value.timestamp().timestamp_millis())
        }
        _ => None,
    }
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
    fn parses_legacy_loves_and_votes() {
        for kind in ["love", "vote"] {
            let interaction = Interaction::from_document(&doc! {
                "projectId": "0000000042",
                "userId": "01USER",
                "type": kind,
            })
            .unwrap();
            assert_eq!(interaction.project_id, "0000000042");
            assert_eq!(interaction.user_id, "01USER");
            assert_eq!(interaction.kind, kind);
        }
    }

    #[test]
    fn rejects_unknown_interaction_types() {
        assert!(
            Interaction::from_document(&doc! {
                "projectId": "0000000042",
                "userId": "01USER",
                "type": "unknown",
            })
            .is_err()
        );
    }
}
