use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use mongodb::Collection;
use mongodb::bson::{Bson, Document, doc};
use serde_json::Value;
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
    collection: &str,
    source: Collection<Document>,
    target: Option<&PgPool>,
    limit: Option<u64>,
) -> Result<()> {
    let mut query = source.find(doc! {}).sort(doc! { "_id": 1 });
    if let Some(limit) = limit {
        query = query.limit(limit as i64);
    }
    let mut cursor = query.await.with_context(|| format!("read {collection}"))?;
    let mut stats = Stats::default();

    while let Some(document) = cursor
        .try_next()
        .await
        .with_context(|| format!("advance {collection} cursor"))?
    {
        stats.source += 1;
        let source_id_hash = safe_source_hash(&document);
        stats.checksum.update(source_id_hash.as_bytes());

        match migrate_document(collection, &document, target).await {
            Ok(()) => stats.migrated += 1,
            Err(error) => {
                stats.rejected += 1;
                if let Some(pool) = target {
                    record_rejection(pool, collection, &source_id_hash, error.reason_code).await?;
                }
                eprintln!(
                    "rejected {collection} record {source_id_hash}: {}",
                    error.safe_log_message()
                );
            }
        }
    }

    let checksum = hex::encode(stats.checksum.clone().finalize());
    if let Some(pool) = target {
        write_checkpoint(pool, collection, &stats, &checksum).await?;
    }
    println!(
        "{collection}: source={} migrated={} rejected={} checksum={} mode={}",
        stats.source,
        stats.migrated,
        stats.rejected,
        checksum,
        if target.is_some() { "write" } else { "dry-run" }
    );

    if stats.rejected > 0 {
        bail!("{collection} migration completed with rejected records")
    }
    Ok(())
}

async fn migrate_document(
    collection: &str,
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    match collection {
        "runtimeConfig" => migrate_runtime_config(document, target).await,
        "illegalList" => migrate_moderation_list(document, target).await,
        "lastPolicyUpdates" => migrate_policy_version(document, target).await,
        _ => Err(RecordError::shape("unsupported collection")),
    }
}

async fn migrate_runtime_config(
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    let key = required_string(document, "id")?;
    let value = bson_json(
        document
            .get("value")
            .cloned()
            .ok_or_else(|| RecordError::shape("missing value"))?,
    )?;

    if let Some(pool) = target {
        sqlx::query(
            "INSERT INTO app.runtime_config (key, value, updated_at)
             VALUES ($1, $2, now())
             ON CONFLICT (key) DO UPDATE SET
                value = EXCLUDED.value,
                updated_at = EXCLUDED.updated_at",
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .map_err(RecordError::write)?;
    }
    Ok(())
}

async fn migrate_moderation_list(
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    const ALLOWED_KEYS: [&str; 8] = [
        "illegalWords",
        "illegalWebsites",
        "spacedOutWordsOnly",
        "potentiallyUnsafeWords",
        "potentiallyUnsafeWordsSpacedOut",
        "legalExtensions",
        "unsafeUsernames",
        "potentiallyUnsafeUsernames",
    ];

    let key = required_string(document, "id")?;
    if !ALLOWED_KEYS.contains(&key.as_str()) {
        return Err(RecordError::shape("unsupported moderation list"));
    }
    let items = string_array(document, "items")?;

    if let Some(pool) = target {
        sqlx::query(
            "INSERT INTO app.moderation_lists (key, items, updated_at)
             VALUES ($1, $2, now())
             ON CONFLICT (key) DO UPDATE SET
                items = EXCLUDED.items,
                updated_at = EXCLUDED.updated_at",
        )
        .bind(key)
        .bind(items)
        .execute(pool)
        .await
        .map_err(RecordError::write)?;
    }
    Ok(())
}

async fn migrate_policy_version(
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    let source_policy = required_string(document, "id")?;
    let policy = match source_policy.as_str() {
        "privacyPolicy" => "privacy",
        "TOS" => "terms",
        "guidelines" => "guidelines",
        _ => return Err(RecordError::shape("unsupported policy")),
    };
    let published_at = timestamp(document, "lastUpdate")
        .ok_or_else(|| RecordError::shape("missing lastUpdate"))?;

    if let Some(pool) = target {
        sqlx::query(
            "INSERT INTO app.policy_versions (policy, published_at)
             VALUES ($1, $2)
             ON CONFLICT (policy) DO UPDATE SET published_at = EXCLUDED.published_at",
        )
        .bind(policy)
        .bind(published_at)
        .execute(pool)
        .await
        .map_err(RecordError::write)?;
    }
    Ok(())
}

async fn write_checkpoint(
    pool: &PgPool,
    collection: &str,
    stats: &Stats,
    checksum: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO migration.checkpoints
            (collection, source_count, migrated_count, rejected_count, checksum, completed_at)
         VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (collection) DO UPDATE SET
            source_count = EXCLUDED.source_count,
            migrated_count = EXCLUDED.migrated_count,
            rejected_count = EXCLUDED.rejected_count,
            checksum = EXCLUDED.checksum,
            updated_at = now(),
            completed_at = EXCLUDED.completed_at",
    )
    .bind(collection)
    .bind(stats.source as i64)
    .bind(stats.migrated as i64)
    .bind(stats.rejected as i64)
    .bind(checksum)
    .execute(pool)
    .await
    .with_context(|| format!("write {collection} checkpoint"))?;
    Ok(())
}

async fn record_rejection(
    pool: &PgPool,
    collection: &str,
    source_id_hash: &str,
    reason_code: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO migration.rejections (collection, source_id_hash, reason_code)
         VALUES ($1, $2, $3)",
    )
    .bind(collection)
    .bind(source_id_hash)
    .bind(reason_code)
    .execute(pool)
    .await
    .context("record safe runtime migration rejection")?;
    Ok(())
}

#[derive(Debug)]
struct RecordError {
    reason_code: &'static str,
    message: String,
}

impl RecordError {
    fn shape(message: impl Into<String>) -> Self {
        Self {
            reason_code: "source-shape",
            message: message.into(),
        }
    }

    fn write(error: sqlx::Error) -> Self {
        Self {
            reason_code: "target-write",
            message: error.to_string(),
        }
    }

    fn safe_log_message(&self) -> &str {
        if self.reason_code == "target-write" {
            "target database rejected record"
        } else {
            &self.message
        }
    }
}

fn required_string(document: &Document, key: &str) -> std::result::Result<String, RecordError> {
    match document.get(key) {
        Some(Bson::String(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(RecordError::shape(format!("missing {key}"))),
    }
}

fn string_array(document: &Document, key: &str) -> std::result::Result<Vec<String>, RecordError> {
    let values = document
        .get_array(key)
        .map_err(|_| RecordError::shape(format!("missing or invalid {key}")))?;
    values
        .iter()
        .map(|value| match value {
            Bson::String(value) => Ok(value.clone()),
            _ => Err(RecordError::shape(format!("non-string item in {key}"))),
        })
        .collect()
}

fn bson_json(value: Bson) -> std::result::Result<Value, RecordError> {
    serde_json::to_value(value).map_err(|_| RecordError::shape("value is not JSON-compatible"))
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

    #[tokio::test]
    async fn validates_runtime_collection_shapes_without_a_database() {
        let fixtures = [
            (
                "runtimeConfig",
                doc! { "id": "viewingEnabled", "value": true },
            ),
            (
                "illegalList",
                doc! { "id": "legalExtensions", "items": ["pen"] },
            ),
            (
                "lastPolicyUpdates",
                doc! { "id": "TOS", "lastUpdate": 1_700_000_000_000_i64 },
            ),
        ];
        for (collection, fixture) in fixtures {
            migrate_document(collection, &fixture, None).await.unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_unknown_list_and_policy_keys() {
        assert!(
            migrate_document("illegalList", &doc! { "id": "unknown", "items": [] }, None,)
                .await
                .is_err()
        );
        assert!(
            migrate_document(
                "lastPolicyUpdates",
                &doc! { "id": "unknown", "lastUpdate": 1_700_000_000_000_i64 },
                None,
            )
            .await
            .is_err()
        );
    }
}
