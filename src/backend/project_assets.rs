use crate::db::Database;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

const PROJECT_ASSET_PREFIX: &str = "project-assets";
const LONG_PUBLIC_CACHE: &str = "public, max-age=31536000, immutable";

#[derive(Deserialize)]
struct AssetQuery {
    asset_name: Option<String>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/projects/backupassetget", get(backup_asset))
        .route(
            "/file/penguinmod-warm-tier-s2-cf/{asset_name}",
            get(warm_tier_asset),
        )
}

async fn backup_asset(
    State(database): State<Database>,
    Query(query): Query<AssetQuery>,
) -> Response {
    serve_asset(database, query.asset_name).await
}

async fn warm_tier_asset(
    State(database): State<Database>,
    Path(asset_name): Path<String>,
) -> Response {
    serve_asset(database, Some(asset_name)).await
}

async fn serve_asset(database: Database, asset_name: Option<String>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    match viewing_enabled(pool).await {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::SERVICE_UNAVAILABLE, "Viewing is disabled"),
        Err(error) => return query_failed(error),
    }

    let asset_name = asset_name.unwrap_or_else(|| "undefined".to_owned());
    if !valid_asset_name(&asset_name) {
        return api_error(StatusCode::BAD_REQUEST, "No asset");
    }
    let token = match blob_token() {
        Ok(token) => token,
        Err(response) => return *response,
    };
    let asset_url = match private_asset_url(&token, &asset_name) {
        Some(url) => url,
        None => {
            tracing::error!("BLOB_READ_WRITE_TOKEN has an invalid store identifier");
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable");
        }
    };
    let storage_response = match reqwest::Client::new()
        .get(asset_url)
        .bearer_auth(token)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "project asset download failed");
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable");
        }
    };
    if storage_response.status() == reqwest::StatusCode::NOT_FOUND {
        return api_error(StatusCode::BAD_REQUEST, "Not found");
    }
    if !storage_response.status().is_success() {
        tracing::error!(status = %storage_response.status(), "project asset storage returned an error");
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable");
    }

    let content_type = storage_response
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/octet-stream"));
    let etag = storage_response.headers().get(header::ETAG).cloned();
    let mut response = Response::new(Body::from_stream(storage_response.bytes_stream()));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(LONG_PUBLIC_CACHE),
    );
    if let Some(etag) = etag {
        response.headers_mut().insert(header::ETAG, etag);
    }
    response
}

async fn viewing_enabled(pool: &PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(
            (SELECT lower(value #>> '{}') = 'true' FROM app.runtime_config WHERE key = 'viewingEnabled'),
            true
        )",
    )
    .fetch_one(pool)
    .await
}

fn valid_asset_name(value: &str) -> bool {
    !value.is_empty()
        && value != "undefined"
        && value.len() <= 512
        && !value.starts_with("0_")
        && value.contains('_')
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains("..")
        && !value.chars().any(char::is_control)
}

fn blob_token() -> Result<String, Box<Response>> {
    std::env::var("BLOB_READ_WRITE_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            tracing::error!("BLOB_READ_WRITE_TOKEN is not configured");
            Box::new(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "StorageUnavailable",
            ))
        })
}

fn private_asset_url(token: &str, asset_name: &str) -> Option<reqwest::Url> {
    let store_id = token.split('_').nth(3)?;
    if store_id.is_empty()
        || !store_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return None;
    }
    let mut url = reqwest::Url::parse(&format!(
        "https://{store_id}.private.blob.vercel-storage.com"
    ))
    .ok()?;
    url.set_path(&format!("/{PROJECT_ASSET_PREFIX}/{asset_name}"));
    Some(url)
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "project asset configuration query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_legacy_asset_names_without_accepting_paths() {
        assert!(valid_asset_name("12345_costume.svg"));
        assert!(!valid_asset_name("0_costume.svg"));
        assert!(!valid_asset_name("costume.svg"));
        assert!(!valid_asset_name("12345_../secret"));
        assert!(!valid_asset_name("12345_folder/file.svg"));
    }

    #[test]
    fn private_asset_urls_stay_on_patternyard_blob_storage() {
        let url = private_asset_url("vercel_blob_rw_store123_secret", "12345_costume.svg")
            .expect("valid token and asset name");
        assert_eq!(
            url.as_str(),
            "https://store123.private.blob.vercel-storage.com/project-assets/12345_costume.svg"
        );
        assert!(!url.as_str().contains("penguinmod.com"));
    }

    #[test]
    fn rejects_store_identifier_host_injection() {
        assert!(
            private_asset_url("vercel_blob_rw_bad.example.com_secret", "12345_costume.svg")
                .is_none()
        );
    }
}
