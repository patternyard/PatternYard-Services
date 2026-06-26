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
        "messages" => migrate_message(document, target).await,
        "userFeed" => migrate_feed_item(document, target).await,
        "reports" => migrate_report(document, target).await,
        _ => Err(RecordError::shape("unsupported collection")),
    }
}

async fn migrate_message(
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    let id = required_string(document, "id")?;
    let receiver_id = required_string(document, "receiver")?;
    let message = required_json_text(document, "message")?;
    let disputable = boolean(document, "disputable");
    let dispute = optional_string(document, "dispute").filter(|value| !value.is_empty());
    let project_id =
        optional_string(document, "projectID").filter(|value| !value.is_empty() && value != "0");
    let is_read = boolean(document, "read");
    let created_at =
        timestamp(document, "date").ok_or_else(|| RecordError::shape("missing date"))?;

    if let Some(pool) = target {
        sqlx::query(
            "INSERT INTO app.messages
                (id, receiver_id, message, disputable, dispute, project_id, is_read, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (id) DO UPDATE SET
                receiver_id = EXCLUDED.receiver_id,
                message = EXCLUDED.message,
                disputable = EXCLUDED.disputable,
                dispute = EXCLUDED.dispute,
                project_id = EXCLUDED.project_id,
                is_read = EXCLUDED.is_read,
                created_at = EXCLUDED.created_at",
        )
        .bind(id)
        .bind(receiver_id)
        .bind(message)
        .bind(disputable)
        .bind(dispute)
        .bind(project_id)
        .bind(is_read)
        .bind(created_at)
        .execute(pool)
        .await
        .map_err(classify_write_error)?;
    }
    Ok(())
}

async fn migrate_feed_item(
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    let user_id = required_string(document, "userID")?;
    let activity_type = required_string(document, "type")?;
    if !matches!(activity_type.as_str(), "follow" | "upload" | "remix") {
        return Err(RecordError::shape("unsupported feed activity type"));
    }
    let target_id = required_string(document, "data")?;
    let created_at =
        timestamp(document, "date").ok_or_else(|| RecordError::shape("missing date"))?;

    if let Some(pool) = target {
        sqlx::query(
            "INSERT INTO app.user_feed (user_id, activity_type, target_id, metadata, created_at)
             SELECT $1, $2, $3, '{}'::jsonb, $4
             WHERE NOT EXISTS (
                SELECT 1 FROM app.user_feed
                WHERE user_id = $1 AND activity_type = $2 AND target_id = $3 AND created_at = $4
             )",
        )
        .bind(user_id)
        .bind(activity_type)
        .bind(target_id)
        .bind(created_at)
        .execute(pool)
        .await
        .map_err(classify_write_error)?;
    }
    Ok(())
}

async fn migrate_report(
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    let id = required_string(document, "id")?;
    let report_type = integer(document, "type")
        .filter(|value| matches!(value, 0 | 1))
        .ok_or_else(|| RecordError::shape("invalid report type"))? as i16;
    let reportee_id = required_string(document, "reportee")?;
    let reporter_id = required_string(document, "reporter")?;
    let reason = required_string(document, "reason")?;
    let created_at =
        timestamp(document, "date").ok_or_else(|| RecordError::shape("missing date"))?;

    if let Some(pool) = target {
        sqlx::query(
            "INSERT INTO app.reports
                (id, report_type, reportee_id, reporter_id, reason, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (reporter_id, reportee_id) DO UPDATE SET
                id = EXCLUDED.id,
                report_type = EXCLUDED.report_type,
                reason = EXCLUDED.reason,
                created_at = EXCLUDED.created_at",
        )
        .bind(id)
        .bind(report_type)
        .bind(reportee_id)
        .bind(reporter_id)
        .bind(reason)
        .bind(created_at)
        .execute(pool)
        .await
        .map_err(classify_write_error)?;
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
    .context("record safe communication migration rejection")?;
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

    fn relationship(message: impl Into<String>) -> Self {
        Self {
            reason_code: "missing-relationship",
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

fn classify_write_error(error: sqlx::Error) -> RecordError {
    if let sqlx::Error::Database(database) = &error
        && database.code().as_deref() == Some("23503")
    {
        return RecordError::relationship("referenced account or project is missing");
    }
    RecordError::write(error)
}

fn required_string(document: &Document, key: &str) -> std::result::Result<String, RecordError> {
    optional_string(document, key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RecordError::shape(format!("missing {key}")))
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

fn required_json_text(document: &Document, key: &str) -> std::result::Result<String, RecordError> {
    let value = document
        .get(key)
        .ok_or_else(|| RecordError::shape(format!("missing {key}")))?;
    let json = match value {
        Bson::String(value) => {
            serde_json::from_str::<Value>(value).unwrap_or_else(|_| Value::String(value.clone()))
        }
        value => bson_to_json(value.clone())?,
    };
    serde_json::to_string(&json).map_err(|_| RecordError::shape("message cannot be serialized"))
}

fn bson_to_json(value: Bson) -> std::result::Result<Value, RecordError> {
    serde_json::to_value(value)
        .map_err(|_| RecordError::shape("message contains unsupported BSON data"))
}

fn boolean(document: &Document, key: &str) -> bool {
    match document.get(key) {
        Some(Bson::Boolean(value)) => *value,
        Some(Bson::Int32(value)) => *value != 0,
        Some(Bson::Int64(value)) => *value != 0,
        _ => false,
    }
}

fn integer(document: &Document, key: &str) -> Option<i64> {
    match document.get(key)? {
        Bson::Int32(value) => Some(i64::from(*value)),
        Bson::Int64(value) => Some(*value),
        Bson::Double(value) if value.is_finite() => Some(*value as i64),
        Bson::String(value) => value.parse().ok(),
        _ => None,
    }
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
    async fn validates_communication_shapes_without_a_database() {
        let fixtures = [
            (
                "messages",
                doc! {
                    "id": "01MESSAGE",
                    "receiver": "01USER",
                    "message": { "type": "notice", "text": "Build saved" },
                    "date": 1_700_000_000_000_i64
                },
            ),
            (
                "userFeed",
                doc! {
                    "userID": "01USER",
                    "type": "upload",
                    "data": "0000000042",
                    "date": 1_700_000_000_000_i64
                },
            ),
            (
                "reports",
                doc! {
                    "id": "01REPORT",
                    "type": 1,
                    "reportee": "0000000042",
                    "reporter": "01USER",
                    "reason": "Needs review",
                    "date": 1_700_000_000_000_i64
                },
            ),
        ];
        for (collection, fixture) in fixtures {
            migrate_document(collection, &fixture, None).await.unwrap();
        }
    }

    #[test]
    fn message_strings_preserve_plain_text_and_json() {
        assert_eq!(
            required_json_text(&doc! { "message": "hello" }, "message").unwrap(),
            "\"hello\""
        );
        assert_eq!(
            required_json_text(&doc! { "message": "{\"type\":\"notice\"}" }, "message").unwrap(),
            "{\"type\":\"notice\"}"
        );
    }

    #[tokio::test]
    async fn rejects_unsupported_feed_and_report_types() {
        assert!(
            migrate_document(
                "userFeed",
                &doc! {
                    "userID": "01USER",
                    "type": "unknown",
                    "data": "target",
                    "date": 1_700_000_000_000_i64
                },
                None,
            )
            .await
            .is_err()
        );
        assert!(
            migrate_document(
                "reports",
                &doc! {
                    "id": "01REPORT",
                    "type": 4,
                    "reportee": "target",
                    "reporter": "01USER",
                    "reason": "review",
                    "date": 1_700_000_000_000_i64
                },
                None,
            )
            .await
            .is_err()
        );
    }
}
