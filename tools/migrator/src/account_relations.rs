use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use mongodb::Collection;
use mongodb::bson::{Bson, Document, doc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

#[derive(Default)]
struct MigrationStats {
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
    let mut stats = MigrationStats::default();

    while let Some(document) = cursor
        .try_next()
        .await
        .with_context(|| format!("advance {collection} cursor"))?
    {
        stats.source += 1;
        let source_id_hash = safe_source_hash(&document);
        stats.checksum.update(source_id_hash.as_bytes());

        let result = migrate_document(collection, &document, target).await;
        match result {
            Ok(()) => stats.migrated += 1,
            Err(error) => {
                stats.rejected += 1;
                if let Some(pool) = target {
                    record_rejection(pool, collection, &source_id_hash, error.reason_code())
                        .await?;
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
        "accountCustomization" => migrate_customization(document, target).await,
        "loggedIPs" => migrate_logged_ip(document, target).await,
        "followers" => migrate_follow(document, target).await,
        "oauthIDs" => migrate_oauth_identity(document, target).await,
        "blocking" => migrate_block(document, target).await,
        _ => Err(RecordError::shape("unsupported collection")),
    }
}

async fn migrate_customization(
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    let username = required_string(document, "username")?;
    let disabled = boolean(document, "disabled");
    let settings = match optional_string(document, "customJson") {
        Some(value) => serde_json::from_str::<serde_json::Value>(&value)
            .map_err(|_| RecordError::shape("customJson is not valid JSON"))?,
        None => serde_json::json!({}),
    };
    if !settings.is_object() {
        return Err(RecordError::shape("customJson is not an object"));
    }

    if let Some(pool) = target {
        let result = sqlx::query(
            "INSERT INTO app.account_customizations (user_id, disabled, settings)
             SELECT id, $2, $3 FROM app.users WHERE username = $1
             ON CONFLICT (user_id) DO UPDATE SET
                disabled = EXCLUDED.disabled,
                settings = EXCLUDED.settings,
                updated_at = now()",
        )
        .bind(username)
        .bind(disabled)
        .bind(settings)
        .execute(pool)
        .await
        .map_err(RecordError::write)?;
        if result.rows_affected() == 0 {
            return Err(RecordError::relationship("customization user is missing"));
        }
    }
    Ok(())
}

async fn migrate_logged_ip(
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    let user_id = required_string(document, "id")?;
    let ip = required_string(document, "ip")?;
    let last_seen_at = timestamp(document, "lastLogin");
    let banned = boolean(document, "banned");

    if let Some(pool) = target {
        let mut transaction = pool.begin().await.map_err(RecordError::write)?;
        sqlx::query(
            "INSERT INTO app.logged_ips (user_id, ip, first_seen_at, last_seen_at)
             VALUES ($1, $2::inet, $3, $3)
             ON CONFLICT (user_id, ip) DO UPDATE SET
                first_seen_at = COALESCE(app.logged_ips.first_seen_at, EXCLUDED.first_seen_at),
                last_seen_at = EXCLUDED.last_seen_at",
        )
        .bind(&user_id)
        .bind(&ip)
        .bind(last_seen_at)
        .execute(&mut *transaction)
        .await
        .map_err(classify_write_error)?;
        if banned {
            sqlx::query(
                "INSERT INTO app.banned_ips (ip, reason)
                 VALUES ($1::inet, 'Migrated legacy IP ban')
                 ON CONFLICT (ip) DO NOTHING",
            )
            .bind(&ip)
            .execute(&mut *transaction)
            .await
            .map_err(RecordError::write)?;
        }
        transaction.commit().await.map_err(RecordError::write)?;
    }
    Ok(())
}

async fn migrate_follow(
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    let follower = required_string(document, "follower")?;
    let target_id = required_string(document, "target")?;
    if follower == target_id {
        return Err(RecordError::shape("self-follow is invalid"));
    }
    let active = document
        .get("active")
        .is_none_or(|_| boolean(document, "active"));

    if let Some(pool) = target {
        sqlx::query(
            "INSERT INTO app.follows (follower_id, target_id, active)
             VALUES ($1, $2, $3)
             ON CONFLICT (follower_id, target_id) DO UPDATE SET
                active = EXCLUDED.active,
                updated_at = now()",
        )
        .bind(follower)
        .bind(target_id)
        .bind(active)
        .execute(pool)
        .await
        .map_err(classify_write_error)?;
    }
    Ok(())
}

async fn migrate_oauth_identity(
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    let user_id = required_string(document, "id")?;
    let provider = required_string(document, "method")?;
    let provider_subject = required_string(document, "code")?;
    if !matches!(provider.as_str(), "scratch" | "github" | "google") {
        return Err(RecordError::shape("unsupported OAuth provider"));
    }

    if let Some(pool) = target {
        sqlx::query(
            "INSERT INTO app.oauth_identities (provider, provider_subject, user_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (provider, provider_subject) DO UPDATE SET
                user_id = EXCLUDED.user_id",
        )
        .bind(provider)
        .bind(provider_subject)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(classify_write_error)?;
    }
    Ok(())
}

async fn migrate_block(
    document: &Document,
    target: Option<&PgPool>,
) -> std::result::Result<(), RecordError> {
    let blocker = required_string(document, "blocker")?;
    let blocked = required_string(document, "target")?;
    if blocker == blocked {
        return Err(RecordError::shape("self-block is invalid"));
    }
    let active = document
        .get("active")
        .is_none_or(|_| boolean(document, "active"));

    if let Some(pool) = target {
        if active {
            sqlx::query(
                "INSERT INTO app.blocks (blocker_id, blocked_id, created_at)
                 VALUES ($1, $2, COALESCE($3, now()))
                 ON CONFLICT (blocker_id, blocked_id) DO NOTHING",
            )
            .bind(blocker)
            .bind(blocked)
            .bind(timestamp(document, "time"))
            .execute(pool)
            .await
            .map_err(classify_write_error)?;
        } else {
            sqlx::query("DELETE FROM app.blocks WHERE blocker_id = $1 AND blocked_id = $2")
                .bind(blocker)
                .bind(blocked)
                .execute(pool)
                .await
                .map_err(RecordError::write)?;
        }
    }
    Ok(())
}

async fn write_checkpoint(
    pool: &PgPool,
    collection: &str,
    stats: &MigrationStats,
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
    .context("record safe migration rejection")?;
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

    fn reason_code(&self) -> &'static str {
        self.reason_code
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
        return RecordError::relationship("referenced user is missing");
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

fn boolean(document: &Document, key: &str) -> bool {
    match document.get(key) {
        Some(Bson::Boolean(value)) => *value,
        Some(Bson::Int32(value)) => *value != 0,
        Some(Bson::Int64(value)) => *value != 0,
        _ => false,
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
    async fn validates_supported_account_relation_shapes_without_a_database() {
        let fixtures = [
            (
                "accountCustomization",
                doc! { "username": "builder", "customJson": "{}" },
            ),
            ("loggedIPs", doc! { "id": "01USER", "ip": "192.0.2.1" }),
            (
                "followers",
                doc! { "follower": "01A", "target": "01B", "active": true },
            ),
            (
                "oauthIDs",
                doc! { "id": "01USER", "method": "github", "code": "42" },
            ),
            (
                "blocking",
                doc! { "blocker": "01A", "target": "01B", "active": true },
            ),
        ];
        for (collection, fixture) in fixtures {
            migrate_document(collection, &fixture, None).await.unwrap();
        }
    }

    #[test]
    fn target_write_errors_have_a_sanitized_log_message() {
        let error = RecordError {
            reason_code: "target-write",
            message: "sensitive database detail".to_owned(),
        };
        assert_eq!(error.safe_log_message(), "target database rejected record");
    }

    #[tokio::test]
    async fn rejects_invalid_relationship_shapes() {
        assert!(
            migrate_document(
                "followers",
                &doc! { "follower": "same", "target": "same" },
                None
            )
            .await
            .is_err()
        );
        assert!(
            migrate_document(
                "oauthIDs",
                &doc! { "id": "01USER", "method": "unknown", "code": "42" },
                None
            )
            .await
            .is_err()
        );
        assert!(
            migrate_document(
                "accountCustomization",
                &doc! { "username": "builder", "customJson": "[]" },
                None
            )
            .await
            .is_err()
        );
    }
}
