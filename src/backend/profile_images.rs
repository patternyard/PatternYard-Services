use crate::auth::authenticate_token;
use crate::db::Database;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use image::imageops::FilterType;
use image::{ImageFormat, ImageReader, Limits};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

const MAX_UPLOAD_BYTES: usize = 5 * 1024 * 1024;

#[derive(Deserialize)]
struct GetProfileImageQuery {
    username: Option<String>,
}

#[derive(Deserialize)]
struct SetProfileImageQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlobUploadResponse {
    url: String,
    pathname: String,
    content_type: String,
    etag: String,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/users/getpfp", get(get_profile_image))
        .route("/api/v1/users/setpfp", post(set_profile_image))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES + 1024 * 1024))
}

async fn get_profile_image(
    State(database): State<Database>,
    Query(query): Query<GetProfileImageQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let username = query
        .username
        .unwrap_or_else(|| "undefined".to_owned())
        .to_lowercase();
    let image_url = match sqlx::query_scalar::<_, Option<String>>(
        "SELECT p.blob_url FROM app.users u \
         LEFT JOIN app.profile_pictures p ON p.user_id = u.id \
         WHERE u.username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(url)) => url,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "NotFound"),
        Err(error) => return query_failed(error),
    };
    let Some(image_url) = image_url else {
        return legacy_image_response(Body::from("false"), None);
    };
    if !is_private_blob_url(&image_url) {
        tracing::error!("stored profile image URL is not a private Vercel Blob URL");
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    }
    let token = match blob_token() {
        Ok(token) => token,
        Err(response) => return *response,
    };
    let response = match reqwest::Client::new()
        .get(image_url)
        .bearer_auth(token)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "profile image download failed");
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable");
        }
    };
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return api_error(StatusCode::NOT_FOUND, "NotFound");
    }
    if !response.status().is_success() {
        tracing::error!(status = %response.status(), "profile image storage returned an error");
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable");
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("image/png"));
    let etag = response.headers().get(header::ETAG).cloned();
    let bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(%error, "profile image response could not be read");
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable");
        }
    };
    legacy_image_response_with_type(Body::from(bytes), content_type, etag)
}

async fn set_profile_image(
    State(database): State<Database>,
    Query(query): Query<SetProfileImageQuery>,
    mut multipart: Multipart,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let token = query.token.unwrap_or_else(|| "undefined".to_owned());
    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };

    let mut picture = None;
    loop {
        let field = match multipart.next_field().await {
            Ok(field) => field,
            Err(error) => {
                tracing::warn!(%error, "invalid profile image multipart upload");
                return api_error(StatusCode::BAD_REQUEST, "Invalid image");
            }
        };
        let Some(field) = field else { break };
        if field.name() != Some("picture") {
            continue;
        }
        picture = match field.bytes().await {
            Ok(bytes) if bytes.len() <= MAX_UPLOAD_BYTES => Some(bytes.to_vec()),
            Ok(_) => return api_error(StatusCode::BAD_REQUEST, "File too large"),
            Err(error) => {
                tracing::warn!(%error, "profile image upload could not be read");
                return api_error(StatusCode::BAD_REQUEST, "Invalid image");
            }
        };
        break;
    }
    let Some(picture) = picture else {
        return api_error(StatusCode::BAD_REQUEST, "No picture was provided");
    };
    let png = match normalize_profile_image(picture).await {
        Ok(png) => png,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, message),
    };
    let token = match blob_token() {
        Ok(token) => token,
        Err(response) => return *response,
    };
    let store_id = match blob_store_id(&token) {
        Some(store_id) => store_id.to_owned(),
        None => {
            tracing::error!("BLOB_READ_WRITE_TOKEN has an invalid format");
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable");
        }
    };
    let pathname = format!("profile-pictures/{}.png", user.id);
    let mut upload_url = reqwest::Url::parse("https://vercel.com/api/blob/")
        .expect("the Vercel Blob API URL is static and valid");
    upload_url
        .query_pairs_mut()
        .append_pair("pathname", &pathname);
    let upload = match reqwest::Client::new()
        .put(upload_url)
        .bearer_auth(token)
        .header("x-api-version", "12")
        .header(
            "x-api-blob-request-id",
            format!("{store_id}:{}", uuid::Uuid::new_v4()),
        )
        .header("x-vercel-blob-store-id", store_id)
        .header("x-api-blob-request-attempt", "0")
        .header("x-vercel-blob-access", "private")
        .header("x-content-type", "image/png")
        .header("x-add-random-suffix", "0")
        .header("x-allow-overwrite", "1")
        .header("x-cache-control-max-age", "60")
        .body(png)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "profile image upload failed");
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable");
        }
    };
    if !upload.status().is_success() {
        tracing::error!(status = %upload.status(), "profile image storage rejected upload");
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable");
    }
    let blob = match upload.json::<BlobUploadResponse>().await {
        Ok(blob) if is_private_blob_url(&blob.url) => blob,
        Ok(_) => {
            tracing::error!("profile image storage returned a non-private URL");
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable");
        }
        Err(error) => {
            tracing::error!(%error, "profile image storage returned invalid metadata");
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable");
        }
    };
    if let Err(error) = sqlx::query(
        "INSERT INTO app.profile_pictures \
         (user_id, blob_url, blob_pathname, content_type, etag, updated_at) \
         VALUES ($1, $2, $3, $4, $5, now()) \
         ON CONFLICT (user_id) DO UPDATE SET \
         blob_url = EXCLUDED.blob_url, blob_pathname = EXCLUDED.blob_pathname, \
         content_type = EXCLUDED.content_type, etag = EXCLUDED.etag, updated_at = now()",
    )
    .bind(user.id)
    .bind(blob.url)
    .bind(blob.pathname)
    .bind(blob.content_type)
    .bind(blob.etag)
    .execute(pool)
    .await
    {
        return query_failed(error);
    }
    Json(SuccessResponse { success: true }).into_response()
}

async fn normalize_profile_image(source: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    tokio::task::spawn_blocking(move || {
        let format = image::guess_format(&source).map_err(|_| "Invalid file type")?;
        if !matches!(format, ImageFormat::Png | ImageFormat::Jpeg) {
            return Err("Invalid file type");
        }
        let mut reader = ImageReader::with_format(Cursor::new(source), format);
        let mut limits = Limits::default();
        limits.max_image_width = Some(8_192);
        limits.max_image_height = Some(8_192);
        limits.max_alloc = Some(128 * 1024 * 1024);
        reader.limits(limits);
        let image = reader.decode().map_err(|_| "Invalid image")?;
        let image = image.resize_exact(100, 100, FilterType::Lanczos3);
        let mut output = Cursor::new(Vec::new());
        image
            .write_to(&mut output, ImageFormat::Png)
            .map_err(|_| "Invalid image")?;
        Ok(output.into_inner())
    })
    .await
    .map_err(|error| {
        tracing::error!(%error, "profile image processing task failed");
        "Invalid image"
    })?
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

fn blob_store_id(token: &str) -> Option<&str> {
    token
        .split('_')
        .nth(3)
        .filter(|store_id| !store_id.is_empty())
}

fn is_private_blob_url(value: &str) -> bool {
    value.parse::<reqwest::Url>().ok().is_some_and(|url| {
        url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|host| host.ends_with(".private.blob.vercel-storage.com"))
    })
}

fn legacy_image_response(body: Body, etag: Option<HeaderValue>) -> Response {
    legacy_image_response_with_type(body, HeaderValue::from_static("image/png"), etag)
}

fn legacy_image_response_with_type(
    body: Body,
    content_type: HeaderValue,
    etag: Option<HeaderValue>,
) -> Response {
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=90"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Some(etag) = etag {
        response.headers_mut().insert(header::ETAG, etag);
    }
    response
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "profile image database query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_token_exposes_only_the_store_id() {
        assert_eq!(
            blob_store_id("vercel_blob_rw_store123_secret"),
            Some("store123")
        );
        assert_eq!(blob_store_id("invalid"), None);
    }

    #[test]
    fn only_private_vercel_blob_urls_are_accepted() {
        assert!(is_private_blob_url(
            "https://store.private.blob.vercel-storage.com/profile-pictures/user.png"
        ));
        assert!(!is_private_blob_url(
            "https://store.public.blob.vercel-storage.com/profile-pictures/user.png"
        ));
        assert!(!is_private_blob_url("https://example.com/avatar.png"));
    }

    #[tokio::test]
    async fn image_normalization_outputs_a_100_pixel_png() {
        let image = image::DynamicImage::new_rgb8(24, 48);
        let mut source = Cursor::new(Vec::new());
        image.write_to(&mut source, ImageFormat::Png).unwrap();

        let normalized = normalize_profile_image(source.into_inner()).await.unwrap();
        assert_eq!(image::guess_format(&normalized).unwrap(), ImageFormat::Png);
        let decoded = image::load_from_memory(&normalized).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (100, 100));
    }
}
