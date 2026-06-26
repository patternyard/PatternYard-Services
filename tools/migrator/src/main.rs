mod account_relations;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use clap::{Parser, Subcommand};
use futures::TryStreamExt;
use mongodb::bson::{Bson, Document, doc};
use mongodb::{Client, Collection};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use std::env;

const COLLECTION_MAP: &str = include_str!("../../../migration/collection-map.json");

#[derive(Parser)]
#[command(name = "patternyard-migrator")]
#[command(about = "Idempotent MongoDB-to-Neon migration tooling for PatternYard")]
struct Cli {
    #[arg(long, env = "MONGODB_DATABASE", default_value = "pm_apidata")]
    source_database: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Audit,
    Migrate {
        #[arg(default_value = "users")]
        collection: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        limit: Option<u64>,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionMap {
    collections: Vec<CollectionMapping>,
}

#[derive(Deserialize)]
struct CollectionMapping {
    source: String,
    #[serde(default)]
    disposition: Option<String>,
}

#[derive(Default)]
struct MigrationStats {
    source: u64,
    migrated: u64,
    rejected: u64,
    checksum: Sha256,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let source_uri = required_env("MONGODB_URI")?;
    let source = Client::with_uri_str(&source_uri)
        .await
        .context("connect to MongoDB")?
        .database(&cli.source_database);

    match cli.command {
        Command::Audit => audit(&source).await,
        Command::Migrate {
            collection,
            dry_run,
            limit,
        } => {
            let target = if dry_run {
                None
            } else {
                let target_uri = required_env("DATABASE_URL")?;
                Some(
                    PgPoolOptions::new()
                        .max_connections(4)
                        .connect(&target_uri)
                        .await
                        .context("connect to Neon")?,
                )
            };

            match collection.as_str() {
                "users" => migrate_users(source.collection("users"), target.as_ref(), limit).await,
                "accountCustomization" | "loggedIPs" | "followers" | "oauthIDs" | "blocking" => {
                    account_relations::migrate(
                        &collection,
                        source.collection(&collection),
                        target.as_ref(),
                        limit,
                    )
                    .await
                }
                _ => bail!(
                    "collection {collection:?} is not implemented yet; run `audit` for the complete inventory"
                ),
            }
        }
    }
}

async fn audit(source: &mongodb::Database) -> Result<()> {
    let map: CollectionMap =
        serde_json::from_str(COLLECTION_MAP).context("parse collection map")?;
    println!("collection\tcount\tdisposition");

    for mapping in map.collections {
        let count = source
            .collection::<Document>(&mapping.source)
            .count_documents(doc! {})
            .await
            .with_context(|| format!("count collection {}", mapping.source))?;
        println!(
            "{}\t{}\t{}",
            mapping.source,
            count,
            mapping.disposition.as_deref().unwrap_or("migrate")
        );
    }

    Ok(())
}

async fn migrate_users(
    source: Collection<Document>,
    target: Option<&PgPool>,
    limit: Option<u64>,
) -> Result<()> {
    let mut query = source.find(doc! {}).sort(doc! { "_id": 1 });
    if let Some(limit) = limit {
        query = query.limit(limit as i64);
    }
    let mut cursor = query.await.context("read users")?;
    let mut stats = MigrationStats::default();

    while let Some(document) = cursor.try_next().await.context("advance users cursor")? {
        stats.source += 1;
        let source_id_hash = safe_source_hash(&document);
        stats.checksum.update(source_id_hash.as_bytes());

        match UserRecord::from_document(&document) {
            Ok(user) => {
                if let Some(pool) = target
                    && let Err(error) = upsert_user(pool, &user).await
                {
                    stats.rejected += 1;
                    record_rejection(pool, "users", &source_id_hash, "target-write").await?;
                    eprintln!("rejected users record {}: {error:#}", source_id_hash);
                    continue;
                }
                stats.migrated += 1;
            }
            Err(error) => {
                stats.rejected += 1;
                if let Some(pool) = target {
                    record_rejection(pool, "users", &source_id_hash, "source-shape").await?;
                }
                eprintln!("rejected users record {}: {error:#}", source_id_hash);
            }
        }
    }

    let checksum = hex::encode(stats.checksum.finalize());
    if let Some(pool) = target {
        sqlx::query(
            "INSERT INTO migration.checkpoints
                (collection, source_count, migrated_count, rejected_count, checksum, completed_at)
             VALUES ('users', $1, $2, $3, $4, now())
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
        .bind(&checksum)
        .execute(pool)
        .await
        .context("write users checkpoint")?;
    }

    println!(
        "users: source={} migrated={} rejected={} checksum={} mode={}",
        stats.source,
        stats.migrated,
        stats.rejected,
        checksum,
        if target.is_some() { "write" } else { "dry-run" }
    );

    if stats.rejected > 0 {
        bail!("users migration completed with rejected records")
    }

    Ok(())
}

struct UserRecord {
    id: String,
    username: String,
    display_username: String,
    password_hash: String,
    token_hash: Option<Vec<u8>>,
    admin: bool,
    moderator: bool,
    permanently_banned: bool,
    unban_at: Option<DateTime<Utc>>,
    ban_reason: String,
    rank: i32,
    badges: Vec<String>,
    following_count: i32,
    follower_count: i32,
    bio: String,
    featured_project_id: Option<String>,
    featured_project_title: Option<String>,
    cubes: i64,
    first_login_at: DateTime<Utc>,
    last_login_at: Option<DateTime<Utc>>,
    last_upload_at: Option<DateTime<Utc>>,
    email: Option<String>,
    email_verified: bool,
    birthday_entered: bool,
    country_entered: bool,
    birth_date: Option<NaiveDate>,
    country_code: Option<String>,
    last_privacy_policy_read_at: Option<DateTime<Utc>>,
    last_terms_read_at: Option<DateTime<Utc>>,
    last_guidelines_read_at: Option<DateTime<Utc>>,
    private_profile: bool,
    allow_following_view: bool,
    is_studio: bool,
    on_watchlist: bool,
}

impl UserRecord {
    fn from_document(document: &Document) -> Result<Self> {
        let id = required_string(document, "id")?;
        let username = required_string(document, "username")?;
        let display_username = optional_string(document, "real_username")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| username.clone());
        let first_login_at = timestamp(document, "firstLogin")
            .or_else(|| timestamp(document, "lastLogin"))
            .context("missing firstLogin and lastLogin")?;

        Ok(Self {
            id,
            username,
            display_username,
            password_hash: optional_string(document, "password").unwrap_or_default(),
            token_hash: optional_string(document, "token")
                .map(|token| hash_bytes(token.as_bytes())),
            admin: boolean(document, "admin"),
            moderator: boolean(document, "moderator"),
            permanently_banned: boolean(document, "permBanned"),
            unban_at: timestamp(document, "unbanTime"),
            ban_reason: optional_string(document, "banReason").unwrap_or_default(),
            rank: integer(document, "rank") as i32,
            badges: string_array(document, "badges"),
            following_count: integer(document, "following").max(0) as i32,
            follower_count: integer(document, "followers").max(0) as i32,
            bio: optional_string(document, "bio").unwrap_or_default(),
            featured_project_id: optional_identifier(document, "featuredProject"),
            featured_project_title: optional_identifier(document, "featuredProjectTitle"),
            cubes: integer(document, "cubes"),
            first_login_at,
            last_login_at: timestamp(document, "lastLogin"),
            last_upload_at: timestamp(document, "lastUpload"),
            email: optional_string(document, "email")
                .map(|email| email.trim().to_lowercase())
                .filter(|email| !email.is_empty()),
            email_verified: boolean(document, "emailVerified"),
            birthday_entered: boolean(document, "birthdayEntered"),
            country_entered: boolean(document, "countryEntered"),
            birth_date: date(document, "birthday"),
            country_code: optional_string(document, "country")
                .map(|country| country.to_uppercase())
                .filter(|country| country.len() == 2),
            last_privacy_policy_read_at: timestamp(document, "lastPrivacyPolicyRead"),
            last_terms_read_at: timestamp(document, "lastTOSRead"),
            last_guidelines_read_at: timestamp(document, "lastGuidelinesRead"),
            private_profile: boolean(document, "privateProfile"),
            allow_following_view: boolean(document, "allowFollowingView"),
            is_studio: boolean(document, "is_studio"),
            on_watchlist: boolean(document, "onWatchlist"),
        })
    }
}

async fn upsert_user(pool: &PgPool, user: &UserRecord) -> Result<()> {
    let mut transaction = pool.begin().await.context("begin user transaction")?;
    upsert_public_user(&mut transaction, user).await?;
    upsert_private_user(&mut transaction, user).await?;
    upsert_session(&mut transaction, user).await?;
    transaction
        .commit()
        .await
        .context("commit user transaction")
}

async fn upsert_public_user(
    transaction: &mut Transaction<'_, Postgres>,
    user: &UserRecord,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO app.users (
            id, username, display_username, password_hash, admin, moderator,
            permanently_banned, unban_at, ban_reason, rank, badges,
            following_count, follower_count, bio, featured_project_id,
            featured_project_title, cubes, first_login_at, last_login_at,
            last_upload_at, email_verified, birthday_entered, country_entered,
            last_privacy_policy_read_at, last_terms_read_at,
            last_guidelines_read_at, private_profile, allow_following_view,
            is_studio, on_watchlist
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
            $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27,
            $28, $29, $30
         )
         ON CONFLICT (id) DO UPDATE SET
            username = EXCLUDED.username,
            display_username = EXCLUDED.display_username,
            password_hash = EXCLUDED.password_hash,
            admin = EXCLUDED.admin,
            moderator = EXCLUDED.moderator,
            permanently_banned = EXCLUDED.permanently_banned,
            unban_at = EXCLUDED.unban_at,
            ban_reason = EXCLUDED.ban_reason,
            rank = EXCLUDED.rank,
            badges = EXCLUDED.badges,
            following_count = EXCLUDED.following_count,
            follower_count = EXCLUDED.follower_count,
            bio = EXCLUDED.bio,
            featured_project_id = EXCLUDED.featured_project_id,
            featured_project_title = EXCLUDED.featured_project_title,
            cubes = EXCLUDED.cubes,
            first_login_at = EXCLUDED.first_login_at,
            last_login_at = EXCLUDED.last_login_at,
            last_upload_at = EXCLUDED.last_upload_at,
            email_verified = EXCLUDED.email_verified,
            birthday_entered = EXCLUDED.birthday_entered,
            country_entered = EXCLUDED.country_entered,
            last_privacy_policy_read_at = EXCLUDED.last_privacy_policy_read_at,
            last_terms_read_at = EXCLUDED.last_terms_read_at,
            last_guidelines_read_at = EXCLUDED.last_guidelines_read_at,
            private_profile = EXCLUDED.private_profile,
            allow_following_view = EXCLUDED.allow_following_view,
            is_studio = EXCLUDED.is_studio,
            on_watchlist = EXCLUDED.on_watchlist,
            updated_at = now()",
    )
    .bind(&user.id)
    .bind(&user.username)
    .bind(&user.display_username)
    .bind(&user.password_hash)
    .bind(user.admin)
    .bind(user.moderator)
    .bind(user.permanently_banned)
    .bind(user.unban_at)
    .bind(&user.ban_reason)
    .bind(user.rank)
    .bind(&user.badges)
    .bind(user.following_count)
    .bind(user.follower_count)
    .bind(&user.bio)
    .bind(&user.featured_project_id)
    .bind(&user.featured_project_title)
    .bind(user.cubes)
    .bind(user.first_login_at)
    .bind(user.last_login_at)
    .bind(user.last_upload_at)
    .bind(user.email_verified)
    .bind(user.birthday_entered)
    .bind(user.country_entered)
    .bind(user.last_privacy_policy_read_at)
    .bind(user.last_terms_read_at)
    .bind(user.last_guidelines_read_at)
    .bind(user.private_profile)
    .bind(user.allow_following_view)
    .bind(user.is_studio)
    .bind(user.on_watchlist)
    .execute(&mut **transaction)
    .await
    .context("upsert public user")?;
    Ok(())
}

async fn upsert_private_user(
    transaction: &mut Transaction<'_, Postgres>,
    user: &UserRecord,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO app.user_private_details (user_id, email, birth_date, country_code)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id) DO UPDATE SET
            email = EXCLUDED.email,
            birth_date = EXCLUDED.birth_date,
            country_code = EXCLUDED.country_code,
            updated_at = now()",
    )
    .bind(&user.id)
    .bind(&user.email)
    .bind(user.birth_date)
    .bind(&user.country_code)
    .execute(&mut **transaction)
    .await
    .context("upsert private user")?;
    Ok(())
}

async fn upsert_session(
    transaction: &mut Transaction<'_, Postgres>,
    user: &UserRecord,
) -> Result<()> {
    let Some(token_hash) = &user.token_hash else {
        return Ok(());
    };

    sqlx::query(
        "INSERT INTO app.sessions
            (token_hash, user_id, issued_at, migrated_from_legacy)
         VALUES ($1, $2, $3, true)
         ON CONFLICT (token_hash) DO UPDATE SET
            user_id = EXCLUDED.user_id,
            issued_at = EXCLUDED.issued_at,
            revoked_at = NULL,
            migrated_from_legacy = true",
    )
    .bind(token_hash)
    .bind(&user.id)
    .bind(user.last_login_at.unwrap_or(user.first_login_at))
    .execute(&mut **transaction)
    .await
    .context("upsert legacy session")?;
    Ok(())
}

async fn record_rejection(
    pool: &PgPool,
    collection: &str,
    source_id_hash: &str,
    reason_code: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO migration.rejections
            (collection, source_id_hash, reason_code)
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

fn required_env(key: &str) -> Result<String> {
    env::var(key)
        .with_context(|| format!("{key} is required"))
        .and_then(|value| {
            if value.is_empty() {
                bail!("{key} must not be empty")
            }
            Ok(value)
        })
}

fn required_string(document: &Document, key: &str) -> Result<String> {
    optional_string(document, key)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("missing {key}"))
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

fn optional_identifier(document: &Document, key: &str) -> Option<String> {
    optional_string(document, key).filter(|value| value != "-1" && !value.is_empty())
}

fn boolean(document: &Document, key: &str) -> bool {
    match document.get(key) {
        Some(Bson::Boolean(value)) => *value,
        Some(Bson::Int32(value)) => *value != 0,
        Some(Bson::Int64(value)) => *value != 0,
        _ => false,
    }
}

fn integer(document: &Document, key: &str) -> i64 {
    match document.get(key) {
        Some(Bson::Int32(value)) => i64::from(*value),
        Some(Bson::Int64(value)) => *value,
        Some(Bson::Double(value)) if value.is_finite() => *value as i64,
        _ => 0,
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

    if millis <= 0 {
        return None;
    }
    DateTime::from_timestamp_millis(millis)
}

fn date(document: &Document, key: &str) -> Option<NaiveDate> {
    match document.get(key)? {
        Bson::DateTime(value) => {
            DateTime::from_timestamp_millis(value.timestamp_millis()).map(|date| date.date_naive())
        }
        Bson::String(value) => value
            .get(..10)
            .and_then(|date| NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()),
        _ => timestamp(document, key).map(|date| date.date_naive()),
    }
}

fn string_array(document: &Document, key: &str) -> Vec<String> {
    document
        .get_array(key)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn safe_source_hash(document: &Document) -> String {
    let source = document
        .get("_id")
        .map(Bson::to_string)
        .unwrap_or_else(|| "missing-id".to_owned());
    hex::encode(hash_bytes(source.as_bytes()))
}

fn hash_bytes(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_legacy_user_without_exposing_raw_token() {
        let source = doc! {
            "_id": "source-record",
            "id": "01USER",
            "username": "builder",
            "real_username": "Builder",
            "password": "$2b$10$preserved",
            "token": "secret-token",
            "firstLogin": 1_700_000_000_000_i64,
            "badges": ["helper"],
            "featuredProject": -1,
            "country": "us"
        };

        let user = UserRecord::from_document(&source).unwrap();
        assert_eq!(user.id, "01USER");
        assert_eq!(user.display_username, "Builder");
        assert_eq!(user.country_code.as_deref(), Some("US"));
        assert!(user.featured_project_id.is_none());
        assert_ne!(user.token_hash.as_deref(), Some("secret-token".as_bytes()));
    }

    #[test]
    fn source_hash_is_stable_and_not_the_source_identifier() {
        let source = doc! { "_id": "private-source-id" };
        let first = safe_source_hash(&source);
        assert_eq!(first, safe_source_hash(&source));
        assert!(!first.contains("private-source-id"));
    }
}
