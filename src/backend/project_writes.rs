use crate::auth::{AuthenticatedUser, authenticate_token};
use crate::db::Database;
use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use image::imageops::FilterType;
use image::{ImageFormat, ImageReader, Limits};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::HashMap;
use std::io::Cursor;

const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROJECT_BYTES: usize = 16 * 1024 * 1024;
const MAX_THUMBNAIL_BYTES: usize = 8 * 1024 * 1024;
const MAX_ASSET_BYTES: usize = 16 * 1024 * 1024;
const MAX_ASSETS: usize = 100;

#[derive(Default)]
struct ProjectForm {
    token: String,
    project_id: String,
    title: String,
    instructions: String,
    notes: String,
    remix: String,
    rating: String,
    project: Option<Vec<u8>>,
    thumbnail: Option<Vec<u8>>,
    assets: Vec<ProjectAsset>,
    assets_field_seen: bool,
}

struct ProjectAsset {
    name: String,
    content_type: String,
    bytes: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct WriteAccess {
    author_id: String,
    hard_rejected: bool,
}

#[derive(sqlx::FromRow)]
struct UploadAccess {
    email_verified: bool,
    rank: i32,
    badges: Vec<String>,
    last_upload_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Default, Debug, PartialEq)]
struct ProjectExtensions {
    ids: Vec<String>,
    urls: HashMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlobUploadResponse {
    pathname: String,
    content_type: String,
}

struct StoredBlob {
    pathname: String,
    content_type: String,
    byte_size: i64,
    checksum: String,
}

#[derive(Serialize)]
struct UploadResponse {
    id: String,
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
        .route("/api/v1/projects/uploadProject", post(upload_project))
        .route("/api/v1/projects/updateProject", post(update_project))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

async fn upload_project(State(database): State<Database>, multipart: Multipart) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    match uploading_enabled(pool).await {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::SERVICE_UNAVAILABLE, "Uploading is disabled"),
        Err(error) => return query_failed(error),
    }

    let form = match read_form(multipart).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    let user = match authenticate_token(pool, &form.token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "Invalid credentials"),
        Err(error) => return query_failed(error),
    };
    let access = match upload_access(pool, &user.id).await {
        Ok(access) => access,
        Err(error) => return query_failed(error),
    };
    if let Err((status, error)) = validate_upload_access(&user, &access) {
        return api_error(status, error);
    }
    if let Err(response) = validate_text(pool, &form).await {
        return response;
    }
    let Some(project_bytes) = form.project.as_deref() else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "Missing json file, thumbnail, or assets",
        );
    };
    let Some(thumbnail_bytes) = form.thumbnail.as_deref() else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "Missing json file, thumbnail, or assets",
        );
    };
    if !form.assets_field_seen {
        return api_error(
            StatusCode::BAD_REQUEST,
            "Missing json file, thumbnail, or assets",
        );
    }
    let extensions = match parse_project_extensions(project_bytes) {
        Ok(extensions) => extensions,
        Err(message) => {
            return api_error_owned(
                StatusCode::BAD_REQUEST,
                format!("Invalid protobuf file: {message}"),
            );
        }
    };
    if let Err(response) = validate_extensions(pool, &user, access.rank, &extensions).await {
        return response;
    }

    let remix = if form.remix.is_empty() {
        "0"
    } else {
        &form.remix
    };
    let remix_id = if remix == "0" {
        None
    } else {
        match project_exists(pool, remix).await {
            Ok(true) => Some(remix.to_owned()),
            Ok(false) => return api_error(StatusCode::BAD_REQUEST, "Remix project does not exist"),
            Err(error) => return query_failed(error),
        }
    };
    let thumbnail = match normalize_thumbnail(thumbnail_bytes).await {
        Ok(thumbnail) => thumbnail,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, message),
    };
    let project_id = match unused_project_id(pool).await {
        Ok(id) => id,
        Err(error) => return query_failed(error),
    };
    let stored =
        match store_project_files(&project_id, project_bytes, &thumbnail, &form.assets).await {
            Ok(stored) => stored,
            Err(response) => return response,
        };

    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = insert_project(
        &mut transaction,
        &project_id,
        &user.id,
        &form,
        remix_id.as_deref(),
        &stored,
    )
    .await
    {
        return query_failed(error);
    }
    if let Err(error) =
        sqlx::query("UPDATE app.users SET last_upload_at = now(), updated_at = now() WHERE id = $1")
            .bind(&user.id)
            .execute(&mut *transaction)
            .await
    {
        return query_failed(error);
    }
    if let Some(original_id) = remix_id
        && let Err(error) = sqlx::query(
            "INSERT INTO app.messages (id, receiver_id, message, disputable, project_id, is_read, created_at) \
             SELECT $1, author_id, $2, false, $3, false, now() \
             FROM app.projects WHERE id = $4 AND author_id <> $5",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(json!({ "type": "remix", "projectID": original_id }).to_string())
        .bind(&project_id)
        .bind(original_id)
        .bind(&user.id)
        .execute(&mut *transaction)
        .await
    {
        return query_failed(error);
    }
    if let Err(error) = transaction.commit().await {
        return query_failed(error);
    }

    (StatusCode::OK, Json(UploadResponse { id: project_id })).into_response()
}

async fn update_project(State(database): State<Database>, multipart: Multipart) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    match uploading_enabled(pool).await {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::SERVICE_UNAVAILABLE, "Uploading is disabled"),
        Err(error) => return query_failed(error),
    }
    let form = match read_form(multipart).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    let user = match authenticate_token(pool, &form.token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "Invalid credentials"),
        Err(error) => return query_failed(error),
    };
    let access = match sqlx::query_as::<_, WriteAccess>(
        "SELECT author_id, hard_rejected FROM app.projects WHERE id = $1",
    )
    .bind(&form.project_id)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(access)) => access,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Project does not exist"),
        Err(error) => return query_failed(error),
    };
    if (access.author_id != user.id || access.hard_rejected) && !user.admin && !user.moderator {
        return api_error(StatusCode::FORBIDDEN, "Unauthorized");
    }
    let upload_access = match upload_access(pool, &user.id).await {
        Ok(access) => access,
        Err(error) => return query_failed(error),
    };
    if let Err((status, error)) = validate_upload_access(&user, &upload_access) {
        return api_error(status, error);
    }
    if let Err(response) = validate_text(pool, &form).await {
        return response;
    }
    if form.project.is_some() != form.assets_field_seen {
        return api_error(StatusCode::BAD_REQUEST, "Missing assets");
    }
    if let Some(project) = form.project.as_deref() {
        let extensions = match parse_project_extensions(project) {
            Ok(extensions) => extensions,
            Err(_) => return api_error(StatusCode::BAD_REQUEST, "Invalid protobuf file"),
        };
        if let Err(response) =
            validate_extensions(pool, &user, upload_access.rank, &extensions).await
        {
            return response;
        }
    }
    let thumbnail = match form.thumbnail.as_deref() {
        Some(thumbnail) => match normalize_thumbnail(thumbnail).await {
            Ok(thumbnail) => Some(thumbnail),
            Err(message) => return api_error(StatusCode::BAD_REQUEST, message),
        },
        None => None,
    };
    let stored = if let Some(project) = form.project.as_deref() {
        match store_project_files(
            &form.project_id,
            project,
            thumbnail.as_deref().unwrap_or(&[]),
            &form.assets,
        )
        .await
        {
            Ok(mut stored) => {
                if thumbnail.is_none() {
                    stored.retain(|(kind, _, _)| *kind != "thumbnail");
                }
                stored
            }
            Err(response) => return response,
        }
    } else if let Some(thumbnail) = thumbnail.as_deref() {
        match upload_blob(
            &format!("project-thumbnails/{}", form.project_id),
            "image/png",
            thumbnail,
        )
        .await
        {
            Ok(blob) => vec![("thumbnail", String::new(), blob)],
            Err(response) => return response,
        }
    } else {
        Vec::new()
    };

    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = sqlx::query(
        "UPDATE app.projects SET title = $2, instructions = $3, notes = $4, rating = $5, updated_at = now() WHERE id = $1",
    )
    .bind(&form.project_id)
    .bind(&form.title)
    .bind(&form.instructions)
    .bind(&form.notes)
    .bind(&form.rating)
    .execute(&mut *transaction)
    .await
    {
        return query_failed(error);
    }
    if form.project.is_some()
        && let Err(error) = sqlx::query(
            "DELETE FROM app.project_blobs WHERE project_id = $1 AND kind IN ('project', 'asset')",
        )
        .bind(&form.project_id)
        .execute(&mut *transaction)
        .await
    {
        return query_failed(error);
    }
    for (kind, asset_name, blob) in &stored {
        if let Err(error) =
            upsert_blob(&mut transaction, &form.project_id, kind, asset_name, blob).await
        {
            return query_failed(error);
        }
    }
    if let Err(error) =
        sqlx::query("UPDATE app.users SET last_upload_at = now(), updated_at = now() WHERE id = $1")
            .bind(&user.id)
            .execute(&mut *transaction)
            .await
    {
        return query_failed(error);
    }
    if let Err(error) = transaction.commit().await {
        return query_failed(error);
    }
    Json(SuccessResponse { success: true }).into_response()
}

async fn read_form(mut multipart: Multipart) -> Result<ProjectForm, Response> {
    let mut form = ProjectForm::default();
    let mut total = 0usize;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid multipart body"))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        let file_name = field.file_name().map(str::to_owned);
        let content_type = field
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_owned();
        if matches!(
            name.as_str(),
            "token" | "projectID" | "title" | "instructions" | "notes" | "remix" | "rating"
        ) {
            let value = field
                .text()
                .await
                .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid multipart body"))?;
            match name.as_str() {
                "token" => form.token = value,
                "projectID" => form.project_id = value,
                "title" => form.title = value,
                "instructions" => form.instructions = value,
                "notes" => form.notes = value,
                "remix" => form.remix = value,
                "rating" => form.rating = value,
                _ => {}
            }
            continue;
        }
        if !matches!(name.as_str(), "jsonFile" | "thumbnail" | "assets") {
            continue;
        }
        let bytes = field
            .bytes()
            .await
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid multipart body"))?
            .to_vec();
        total = total.saturating_add(bytes.len());
        if total > MAX_BODY_BYTES {
            return Err(api_error(StatusCode::PAYLOAD_TOO_LARGE, "File too large"));
        }
        match name.as_str() {
            "jsonFile" if bytes.len() <= MAX_PROJECT_BYTES => form.project = Some(bytes),
            "thumbnail" if bytes.len() <= MAX_THUMBNAIL_BYTES => form.thumbnail = Some(bytes),
            "assets" if bytes.len() <= MAX_ASSET_BYTES && form.assets.len() < MAX_ASSETS => {
                form.assets_field_seen = true;
                let asset_name = file_name
                    .filter(|name| valid_asset_name(name))
                    .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "Invalid asset name"))?;
                form.assets.push(ProjectAsset {
                    name: asset_name,
                    content_type,
                    bytes,
                });
            }
            _ => return Err(api_error(StatusCode::PAYLOAD_TOO_LARGE, "File too large")),
        }
    }
    Ok(form)
}

fn validate_upload_access(
    user: &AuthenticatedUser,
    access: &UploadAccess,
) -> Result<(), (StatusCode, &'static str)> {
    if !access.email_verified {
        return Err((
            StatusCode::BAD_REQUEST,
            "You must verify your email to upload a project",
        ));
    }
    let donor = access.badges.iter().any(|badge| badge == "donator");
    if !donor
        && !user.admin
        && !user.moderator
        && access
            .last_upload_at
            .is_some_and(|last| last > chrono::Utc::now() - chrono::Duration::minutes(8))
    {
        return Err((StatusCode::BAD_REQUEST, "Uploaded in the last 8 minutes"));
    }
    Ok(())
}

async fn validate_text(pool: &PgPool, form: &ProjectForm) -> Result<(), Response> {
    if form.title.chars().count() > 100
        || form.instructions.chars().count() > 4096
        || form.notes.chars().count() > 4096
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "title, instructions, or notes are too long",
        ));
    }
    let blocked = sqlx::query_scalar::<_, String>(
        "SELECT unnest(items) FROM app.moderation_lists WHERE key IN ('illegalWords', 'illegalWebsites', 'spacedOutWordsOnly')",
    )
    .fetch_all(pool)
    .await
    .map_err(query_failed)?;
    let text = format!("{}\n{}\n{}", form.title, form.instructions, form.notes).to_lowercase();
    if blocked
        .iter()
        .any(|item| !item.is_empty() && text.contains(&item.to_lowercase()))
    {
        return Err(api_error(StatusCode::BAD_REQUEST, "IllegalWordsUsed"));
    }
    Ok(())
}

async fn validate_extensions(
    pool: &PgPool,
    user: &AuthenticatedUser,
    rank: i32,
    project: &ProjectExtensions,
) -> Result<(), Response> {
    if rank >= 1 || user.admin || user.moderator {
        return Ok(());
    }
    let allowed = sqlx::query_scalar::<_, Vec<String>>(
        "SELECT items FROM app.moderation_lists WHERE key = 'legalExtensions'",
    )
    .fetch_optional(pool)
    .await
    .map_err(query_failed)?
    .unwrap_or_default();
    for id in &project.ids {
        let permitted = if let Some(url) = project.urls.get(id) {
            allowed
                .iter()
                .any(|source| source.starts_with("https://") && url.starts_with(source))
        } else {
            allowed.contains(id)
        };
        if !permitted {
            return Err(api_error_owned(
                StatusCode::BAD_REQUEST,
                format!("Extension not allowed: {id}"),
            ));
        }
    }
    Ok(())
}

async fn store_project_files(
    project_id: &str,
    project: &[u8],
    thumbnail: &[u8],
    assets: &[ProjectAsset],
) -> Result<Vec<(&'static str, String, StoredBlob)>, Response> {
    let mut stored = Vec::with_capacity(assets.len() + 2);
    stored.push((
        "project",
        String::new(),
        upload_blob(
            &format!("projects/{project_id}"),
            "application/octet-stream",
            project,
        )
        .await?,
    ));
    if !thumbnail.is_empty() {
        stored.push((
            "thumbnail",
            String::new(),
            upload_blob(
                &format!("project-thumbnails/{project_id}"),
                "image/png",
                thumbnail,
            )
            .await?,
        ));
    }
    for asset in assets {
        stored.push((
            "asset",
            asset.name.clone(),
            upload_blob(
                &format!("project-assets/{project_id}_{}", asset.name),
                &asset.content_type,
                &asset.bytes,
            )
            .await?,
        ));
    }
    Ok(stored)
}

async fn upload_blob(
    pathname: &str,
    content_type: &str,
    bytes: &[u8],
) -> Result<StoredBlob, Response> {
    let token = std::env::var("BLOB_READ_WRITE_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable"))?;
    let store_id = token
        .split('_')
        .nth(3)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable"))?;
    let mut url = reqwest::Url::parse("https://vercel.com/api/blob/").expect("static Blob API URL");
    url.query_pairs_mut().append_pair("pathname", pathname);
    let response = reqwest::Client::new()
        .put(url)
        .bearer_auth(&token)
        .header("x-api-version", "12")
        .header(
            "x-api-blob-request-id",
            format!("{store_id}:{}", uuid::Uuid::new_v4()),
        )
        .header("x-vercel-blob-store-id", store_id)
        .header("x-api-blob-request-attempt", "0")
        .header("x-vercel-blob-access", "private")
        .header("x-content-type", content_type)
        .header("x-add-random-suffix", "0")
        .header("x-allow-overwrite", "1")
        .body(bytes.to_vec())
        .send()
        .await
        .map_err(|error| {
            tracing::error!(%error, %pathname, "project Blob upload failed");
            api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable")
        })?;
    if !response.status().is_success() {
        tracing::error!(status = %response.status(), %pathname, "project Blob upload rejected");
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "StorageUnavailable",
        ));
    }
    let blob = response
        .json::<BlobUploadResponse>()
        .await
        .map_err(|error| {
            tracing::error!(%error, %pathname, "project Blob upload returned invalid metadata");
            api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable")
        })?;
    if blob.pathname != pathname {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "StorageUnavailable",
        ));
    }
    Ok(StoredBlob {
        pathname: blob.pathname,
        content_type: blob.content_type,
        byte_size: bytes.len() as i64,
        checksum: format!("{:x}", Sha256::digest(bytes)),
    })
}

async fn insert_project(
    transaction: &mut Transaction<'_, Postgres>,
    project_id: &str,
    author_id: &str,
    form: &ProjectForm,
    remix_id: Option<&str>,
    blobs: &[(&str, String, StoredBlob)],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO app.projects (id, author_id, title, instructions, notes, remix_of_id, rating, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())",
    )
    .bind(project_id)
    .bind(author_id)
    .bind(&form.title)
    .bind(&form.instructions)
    .bind(&form.notes)
    .bind(remix_id)
    .bind(&form.rating)
    .execute(&mut **transaction)
    .await?;
    for (kind, asset_name, blob) in blobs {
        upsert_blob(transaction, project_id, kind, asset_name, blob).await?;
    }
    sqlx::query(
        "INSERT INTO app.user_feed (user_id, activity_type, target_id, metadata, created_at) VALUES ($1, $2, $3, $4, now())",
    )
    .bind(author_id)
    .bind(if remix_id.is_some() { "remix" } else { "upload" })
    .bind(project_id)
    .bind(json!({ "projectID": project_id }))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn upsert_blob(
    transaction: &mut Transaction<'_, Postgres>,
    project_id: &str,
    kind: &str,
    asset_name: &str,
    blob: &StoredBlob,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO app.project_blobs (project_id, kind, asset_name, blob_path, content_type, byte_size, checksum, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now()) \
         ON CONFLICT (project_id, kind, asset_name) DO UPDATE SET blob_path = EXCLUDED.blob_path, content_type = EXCLUDED.content_type, byte_size = EXCLUDED.byte_size, checksum = EXCLUDED.checksum, updated_at = now()",
    )
    .bind(project_id)
    .bind(kind)
    .bind(asset_name)
    .bind(&blob.pathname)
    .bind(&blob.content_type)
    .bind(blob.byte_size)
    .bind(&blob.checksum)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn upload_access(pool: &PgPool, user_id: &str) -> Result<UploadAccess, sqlx::Error> {
    sqlx::query_as::<_, UploadAccess>(
        "SELECT email_verified, rank, badges, last_upload_at FROM app.users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
}

async fn uploading_enabled(pool: &PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE((SELECT lower(value #>> '{}') = 'true' FROM app.runtime_config WHERE key = 'uploadingEnabled'), true)",
    )
    .fetch_one(pool)
    .await
}

async fn project_exists(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM app.projects WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
}

async fn unused_project_id(pool: &PgPool) -> Result<String, sqlx::Error> {
    for _ in 0..20 {
        let random: u64 = rand::random();
        let id = format!("{:010}", random % 10_000_000_000);
        if !project_exists(pool, &id).await? {
            return Ok(id);
        }
    }
    Err(sqlx::Error::Protocol(
        "could not allocate project ID".into(),
    ))
}

async fn normalize_thumbnail(source: &[u8]) -> Result<Vec<u8>, &'static str> {
    let source = source.to_vec();
    tokio::task::spawn_blocking(move || {
        let format = image::guess_format(&source).map_err(|_| "Invalid image")?;
        if !matches!(format, ImageFormat::Png | ImageFormat::Jpeg) {
            return Err("Invalid image");
        }
        let mut reader = ImageReader::with_format(Cursor::new(source), format);
        let mut limits = Limits::default();
        limits.max_image_width = Some(8_192);
        limits.max_image_height = Some(8_192);
        limits.max_alloc = Some(128 * 1024 * 1024);
        reader.limits(limits);
        let image = reader.decode().map_err(|_| "Invalid image")?;
        let image = image.resize_exact(240, 180, FilterType::Lanczos3);
        let mut output = Cursor::new(Vec::new());
        image
            .write_to(&mut output, ImageFormat::Png)
            .map_err(|_| "Invalid image")?;
        Ok(output.into_inner())
    })
    .await
    .map_err(|_| "Invalid image")?
}

fn valid_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && !name.chars().any(char::is_control)
}

fn parse_project_extensions(bytes: &[u8]) -> Result<ProjectExtensions, &'static str> {
    let mut offset = 0;
    let mut result = ProjectExtensions::default();
    while offset < bytes.len() {
        let key = read_varint(bytes, &mut offset)?;
        let field = key >> 3;
        let wire = key & 7;
        if field == 0 {
            return Err("invalid field");
        }
        if field == 7 && wire == 2 {
            result.ids.push(read_string(bytes, &mut offset)?);
        } else if field == 8 && wire == 2 {
            let entry = read_slice(bytes, &mut offset)?;
            let (key, value) = parse_string_map_entry(entry)?;
            result.urls.insert(key, value);
        } else {
            skip_field(bytes, &mut offset, wire)?;
        }
    }
    Ok(result)
}

fn parse_string_map_entry(bytes: &[u8]) -> Result<(String, String), &'static str> {
    let mut offset = 0;
    let mut key_value = String::new();
    let mut value = String::new();
    while offset < bytes.len() {
        let tag = read_varint(bytes, &mut offset)?;
        match (tag >> 3, tag & 7) {
            (1, 2) => key_value = read_string(bytes, &mut offset)?,
            (2, 2) => value = read_string(bytes, &mut offset)?,
            (_, wire) => skip_field(bytes, &mut offset, wire)?,
        }
    }
    Ok((key_value, value))
}

fn read_varint(bytes: &[u8], offset: &mut usize) -> Result<u64, &'static str> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*offset).ok_or("truncated protobuf")?;
        *offset += 1;
        if shift == 63 && byte > 1 {
            return Err("invalid varint");
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("invalid varint")
}

fn read_slice<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8], &'static str> {
    let length = usize::try_from(read_varint(bytes, offset)?).map_err(|_| "invalid length")?;
    let end = offset.checked_add(length).ok_or("invalid length")?;
    let value = bytes.get(*offset..end).ok_or("truncated protobuf")?;
    *offset = end;
    Ok(value)
}

fn read_string(bytes: &[u8], offset: &mut usize) -> Result<String, &'static str> {
    String::from_utf8(read_slice(bytes, offset)?.to_vec()).map_err(|_| "invalid string")
}

fn skip_field(bytes: &[u8], offset: &mut usize, wire: u64) -> Result<(), &'static str> {
    match wire {
        0 => {
            read_varint(bytes, offset)?;
        }
        1 => {
            *offset = offset
                .checked_add(8)
                .filter(|end| *end <= bytes.len())
                .ok_or("truncated protobuf")?
        }
        2 => {
            read_slice(bytes, offset)?;
        }
        5 => {
            *offset = offset
                .checked_add(4)
                .filter(|end| *end <= bytes.len())
                .ok_or("truncated protobuf")?
        }
        _ => return Err("unsupported wire type"),
    }
    Ok(())
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "project write query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, error: &'static str) -> Response {
    (status, Json(ErrorBody { error })).into_response()
}

fn api_error_owned(status: StatusCode, error: String) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_extension_ids_and_urls_from_project_protobuf() {
        let bytes = [
            0x3a, 0x03, b'p', b'e', b'n', 0x42, 0x1c, 0x0a, 0x03, b'p', b'e', b'n', 0x12, 0x15,
            b'h', b't', b't', b'p', b's', b':', b'/', b'/', b'p', b'a', b't', b't', b'e', b'r',
            b'n', b'y', b'a', b'r', b'd', b'.', b'd',
        ];
        let parsed = parse_project_extensions(&bytes).expect("valid protobuf");
        assert_eq!(parsed.ids, vec!["pen"]);
        assert_eq!(
            parsed.urls.get("pen"),
            Some(&"https://patternyard.d".to_owned())
        );
    }

    #[test]
    fn rejects_truncated_project_protobuf() {
        assert_eq!(
            parse_project_extensions(&[0x3a, 0x04, b'a']).unwrap_err(),
            "truncated protobuf"
        );
    }

    #[test]
    fn asset_names_cannot_escape_the_project_prefix() {
        assert!(valid_asset_name("costume.svg"));
        assert!(!valid_asset_name("../costume.svg"));
        assert!(!valid_asset_name("folder/costume.svg"));
    }
}
