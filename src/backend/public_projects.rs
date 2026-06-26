use crate::auth::authenticate_token;
use crate::db::Database;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, QueryBuilder};
use std::net::IpAddr;

const DEFAULT_PAGE_SIZE: i64 = 20;
const MAX_PAGE_SIZE: i64 = 100;
const MAX_PROJECT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_WRAPPER_BYTES: u64 = 64 * 1024 * 1024;
const SHORT_PUBLIC_CACHE: &str = "public, max-age=90";

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PageQuery {
    page: Option<i64>,
    reverse: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectQuery {
    request_type: Option<String>,
    #[serde(alias = "projectID")]
    project_id: Option<String>,
    token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WrapperQuery {
    project_id: Option<String>,
    token: Option<String>,
    assets: Option<String>,
    load_assets_locally: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ProjectAccess {
    author_id: String,
    is_public: bool,
    hard_rejected: bool,
    metadata: Value,
}

#[derive(sqlx::FromRow)]
struct ProjectBlob {
    asset_name: String,
    blob_path: String,
    content_type: Option<String>,
}

#[derive(Serialize)]
struct LegacyBuffer {
    #[serde(rename = "type")]
    kind: &'static str,
    data: Vec<u8>,
}

#[derive(Serialize)]
struct LegacyAsset {
    id: String,
    buffer: LegacyBuffer,
}

#[derive(Serialize)]
struct WrapperResponse {
    project: LegacyBuffer,
    assets: Vec<LegacyAsset>,
}

#[derive(Deserialize, Default)]
struct RandomQuery {
    n: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemixQuery {
    project_id: Option<String>,
    page: Option<i64>,
}

#[derive(Deserialize, Default)]
struct SearchQuery {
    query: Option<String>,
    page: Option<i64>,
    #[serde(rename = "type")]
    sort: Option<String>,
    reverse: Option<bool>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

#[derive(Clone, Copy)]
enum ProjectOrder {
    LastUpdate,
    UploadDate,
    Views,
    Loves,
    Votes,
    Random,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/projects/getproject", get(get_project))
        .route(
            "/api/v1/projects/getprojectwrapper",
            get(get_project_wrapper),
        )
        .route("/{id}", get(project_redirect))
        .route("/api/v1/projects/getprojects", get(get_projects))
        .route(
            "/api/v1/projects/getfeaturedprojects",
            get(get_featured_projects),
        )
        .route(
            "/api/v1/projects/getrandomproject",
            get(get_random_projects),
        )
        .route("/api/v1/projects/getremixes", get(get_remixes))
        .route("/api/v1/projects/searchprojects", get(search_projects))
}

async fn get_project(
    State(database): State<Database>,
    headers: HeaderMap,
    Query(query): Query<ProjectQuery>,
) -> Response {
    let Some(request_type) = non_empty(query.request_type) else {
        return api_error(StatusCode::BAD_REQUEST, "Missing requestType");
    };
    let Some(project_id) = non_empty(query.project_id) else {
        return api_error(StatusCode::BAD_REQUEST, "Missing projectId");
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    match viewing_enabled(pool).await {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::SERVICE_UNAVAILABLE, "Viewing is disabled"),
        Err(error) => return query_failed(error),
    }
    let access = match project_access(pool, &project_id).await {
        Ok(Some(access)) => access,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "Project not found"),
        Err(error) => return query_failed(error),
    };
    let user = match authenticate_token(pool, query.token.as_deref().unwrap_or("")).await {
        Ok(user) => user,
        Err(error) => return query_failed(error),
    };
    let is_author = user
        .as_ref()
        .is_some_and(|user| user.id == access.author_id);
    let is_staff = user
        .as_ref()
        .is_some_and(|user| user.admin || user.moderator);
    if ((!is_author && !access.is_public) || access.hard_rejected) && !is_staff {
        return api_error(StatusCode::NOT_FOUND, "Project not found");
    }

    match request_type.as_str() {
        "metadata" => Json(access.metadata).into_response(),
        "protobuf" => {
            if let Err(error) = register_view(pool, &project_id, &headers).await {
                return query_failed(error);
            }
            match fetch_project_blob(pool, &project_id, "project", "", MAX_PROJECT_FILE_BYTES).await
            {
                Ok(Some((bytes, _))) => binary_response(bytes, "application/json", None),
                Ok(None) => api_error(StatusCode::NOT_FOUND, "Project not found"),
                Err(response) => response,
            }
        }
        "thumbnail" => {
            match fetch_project_blob(pool, &project_id, "thumbnail", "", MAX_PROJECT_FILE_BYTES)
                .await
            {
                Ok(Some((bytes, content_type))) => binary_response(
                    bytes,
                    content_type.as_deref().unwrap_or("image/png"),
                    Some(SHORT_PUBLIC_CACHE),
                ),
                Ok(None) => api_error(StatusCode::NOT_FOUND, "Thumbnail not found"),
                Err(response) => response,
            }
        }
        "assets" => match fetch_project_assets(pool, &project_id, MAX_WRAPPER_BYTES).await {
            Ok(assets) => {
                ([(header::CACHE_CONTROL, SHORT_PUBLIC_CACHE)], Json(assets)).into_response()
            }
            Err(response) => response,
        },
        _ => api_error(StatusCode::BAD_REQUEST, "Invalid requestType"),
    }
}

async fn get_project_wrapper(
    State(database): State<Database>,
    headers: HeaderMap,
    Query(query): Query<WrapperQuery>,
) -> Response {
    let Some(project_id) = non_empty(query.project_id) else {
        return api_error(StatusCode::BAD_REQUEST, "Missing projectId");
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    match viewing_enabled(pool).await {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::SERVICE_UNAVAILABLE, "Viewing is disabled"),
        Err(error) => return query_failed(error),
    }
    let access = match project_access(pool, &project_id).await {
        Ok(Some(access)) => access,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "Project not found"),
        Err(error) => return query_failed(error),
    };
    let user = match authenticate_token(pool, query.token.as_deref().unwrap_or("")).await {
        Ok(user) => user,
        Err(error) => return query_failed(error),
    };
    let is_author = user
        .as_ref()
        .is_some_and(|user| user.id == access.author_id);
    if !is_author && (!access.is_public || access.hard_rejected) {
        return api_error(StatusCode::NOT_FOUND, "Project not found");
    }
    if let Err(error) = register_view(pool, &project_id, &headers).await {
        return query_failed(error);
    }
    let project =
        match fetch_project_blob(pool, &project_id, "project", "", MAX_PROJECT_FILE_BYTES).await {
            Ok(Some((bytes, _))) => LegacyBuffer {
                kind: "Buffer",
                data: bytes,
            },
            Ok(None) => return api_error(StatusCode::NOT_FOUND, "Project not found"),
            Err(response) => return response,
        };
    let include_assets = query.assets.as_deref() != Some("false")
        || query.load_assets_locally.as_deref() == Some("true");
    let assets = if include_assets {
        let remaining = MAX_WRAPPER_BYTES.saturating_sub(project.data.len() as u64);
        match fetch_project_assets(pool, &project_id, remaining).await {
            Ok(assets) => assets,
            Err(response) => return response,
        }
    } else {
        Vec::new()
    };

    Json(WrapperResponse { project, assets }).into_response()
}

async fn project_redirect(
    State(database): State<Database>,
    Path(project_id): Path<String>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let access = match project_access(pool, &project_id).await {
        Ok(Some(access)) if access.is_public && !access.hard_rejected => access,
        Ok(_) => return api_error(StatusCode::NOT_FOUND, "Not Found"),
        Err(error) => return query_failed(error),
    };
    let title = access
        .metadata
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Project");
    let instructions = access
        .metadata
        .get("instructions")
        .and_then(Value::as_str)
        .unwrap_or("");
    let notes = access
        .metadata
        .get("notes")
        .and_then(Value::as_str)
        .unwrap_or("");
    let author = access
        .metadata
        .pointer("/author/username")
        .and_then(Value::as_str)
        .unwrap_or("PatternYard creator");
    let html = project_page(&project_id, title, instructions, notes, author);
    ([(header::CACHE_CONTROL, "public, max-age=60")], Html(html)).into_response()
}

async fn get_projects(
    State(database): State<Database>,
    Query(query): Query<PageQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let order = ProjectOrder::LastUpdate;
    let ascending = query.reverse.unwrap_or(false);

    respond_with_projects(
        fetch_projects(
            pool,
            None,
            None,
            false,
            order,
            ascending,
            page(query.page),
            DEFAULT_PAGE_SIZE,
        )
        .await,
    )
}

async fn get_featured_projects(
    State(database): State<Database>,
    Query(query): Query<PageQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    respond_with_projects(
        fetch_projects(
            pool,
            None,
            None,
            true,
            ProjectOrder::UploadDate,
            false,
            page(query.page),
            DEFAULT_PAGE_SIZE,
        )
        .await,
    )
}

async fn get_random_projects(
    State(database): State<Database>,
    Query(query): Query<RandomQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let count = query.n.unwrap_or(1).clamp(0, DEFAULT_PAGE_SIZE);

    respond_with_projects(
        fetch_projects(
            pool,
            None,
            None,
            false,
            ProjectOrder::Random,
            false,
            0,
            count,
        )
        .await,
    )
}

async fn get_remixes(
    State(database): State<Database>,
    Query(query): Query<RemixQuery>,
) -> Response {
    let Some(project_id) = non_empty(query.project_id) else {
        return api_error(StatusCode::BAD_REQUEST, "Missing projectID");
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    respond_with_projects(
        fetch_projects(
            pool,
            None,
            Some(&project_id),
            false,
            ProjectOrder::LastUpdate,
            false,
            page(query.page),
            DEFAULT_PAGE_SIZE,
        )
        .await,
    )
}

async fn search_projects(
    State(database): State<Database>,
    Query(query): Query<SearchQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let order = match query.sort.as_deref() {
        Some("newest") => ProjectOrder::LastUpdate,
        Some("uploaddate") | Some("featured") => ProjectOrder::UploadDate,
        Some("loves") => ProjectOrder::Loves,
        Some("votes") => ProjectOrder::Votes,
        _ => ProjectOrder::Views,
    };

    respond_with_projects(
        fetch_projects(
            pool,
            Some(query.query.as_deref().unwrap_or("")),
            None,
            query.sort.as_deref() == Some("featured"),
            order,
            query.reverse.unwrap_or(false),
            page(query.page),
            DEFAULT_PAGE_SIZE,
        )
        .await,
    )
}

async fn project_access(
    pool: &PgPool,
    project_id: &str,
) -> Result<Option<ProjectAccess>, sqlx::Error> {
    sqlx::query_as::<_, ProjectAccess>(
        "SELECT p.author_id, p.is_public, p.hard_rejected, \
         jsonb_build_object(\
            'id', p.id, \
            'title', p.title, \
            'author', jsonb_build_object('id', u.id, 'username', u.username), \
            'instructions', p.instructions, \
            'notes', p.notes, \
            'rating', p.rating, \
            'public', p.is_public, \
            'featured', p.featured, \
            'softRejected', p.soft_rejected, \
            'hardReject', p.hard_rejected, \
            'noFeature', p.no_feature, \
            'modMessage', p.moderation_message, \
            'loves', p.loves, \
            'votes', p.votes, \
            'views', p.views, \
            'impressions', p.impressions, \
            'date', floor(extract(epoch FROM p.created_at) * 1000)::bigint, \
            'lastUpdate', floor(extract(epoch FROM p.updated_at) * 1000)::bigint, \
            'remix', p.remix_of_id, \
            'fromDonator', 'donator' = ANY(u.badges)\
         ) AS metadata \
         FROM app.projects p \
         JOIN app.users u ON u.id = p.author_id \
         WHERE p.id = $1",
    )
    .bind(project_id)
    .fetch_optional(pool)
    .await
}

async fn fetch_project_blob(
    pool: &PgPool,
    project_id: &str,
    kind: &str,
    asset_name: &str,
    max_bytes: u64,
) -> Result<Option<(Vec<u8>, Option<String>)>, Response> {
    let blob = sqlx::query_as::<_, ProjectBlob>(
        "SELECT asset_name, blob_path, content_type FROM app.project_blobs \
         WHERE project_id = $1 AND kind = $2 AND asset_name = $3",
    )
    .bind(project_id)
    .bind(kind)
    .bind(asset_name)
    .fetch_optional(pool)
    .await
    .map_err(query_failed)?;
    let Some(blob) = blob else {
        return Ok(None);
    };
    let bytes = download_private_blob(&blob.blob_path, max_bytes).await?;
    Ok(Some((bytes, blob.content_type)))
}

async fn fetch_project_assets(
    pool: &PgPool,
    project_id: &str,
    max_bytes: u64,
) -> Result<Vec<LegacyAsset>, Response> {
    let blobs = sqlx::query_as::<_, ProjectBlob>(
        "SELECT asset_name, blob_path, content_type FROM app.project_blobs \
         WHERE project_id = $1 AND kind = 'asset' ORDER BY asset_name ASC",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(query_failed)?;
    let mut remaining = max_bytes;
    let mut assets = Vec::with_capacity(blobs.len());
    for blob in blobs {
        let bytes = download_private_blob(&blob.blob_path, remaining).await?;
        remaining = remaining.saturating_sub(bytes.len() as u64);
        assets.push(LegacyAsset {
            id: blob.asset_name,
            buffer: LegacyBuffer {
                kind: "Buffer",
                data: bytes,
            },
        });
    }
    Ok(assets)
}

async fn download_private_blob(pathname: &str, max_bytes: u64) -> Result<Vec<u8>, Response> {
    let token = std::env::var("BLOB_READ_WRITE_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable"))?;
    let url = private_blob_url(&token, pathname)
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable"))?;
    let response = reqwest::Client::new()
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| {
            tracing::error!(%error, %pathname, "project Blob download failed");
            api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable")
        })?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(api_error(StatusCode::NOT_FOUND, "Project file not found"));
    }
    if !response.status().is_success() {
        tracing::error!(status = %response.status(), %pathname, "project Blob download rejected");
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "StorageUnavailable",
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes)
    {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Project file too large",
        ));
    }
    let bytes = response.bytes().await.map_err(|error| {
        tracing::error!(%error, %pathname, "project Blob body read failed");
        api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable")
    })?;
    if bytes.len() as u64 > max_bytes {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Project file too large",
        ));
    }
    Ok(bytes.to_vec())
}

fn private_blob_url(token: &str, pathname: &str) -> Option<reqwest::Url> {
    let store_id = token.split('_').nth(3)?;
    if store_id.is_empty()
        || !store_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
        || pathname.is_empty()
        || pathname.starts_with('/')
        || pathname.contains("..")
        || pathname.contains('\\')
    {
        return None;
    }
    let mut url = reqwest::Url::parse(&format!(
        "https://{store_id}.private.blob.vercel-storage.com"
    ))
    .ok()?;
    url.set_path(pathname);
    Some(url)
}

async fn register_view(
    pool: &PgPool,
    project_id: &str,
    headers: &HeaderMap,
) -> Result<(), sqlx::Error> {
    let Some(ip) = client_ip(headers) else {
        return Ok(());
    };
    let viewer_hash = Sha256::digest(ip.to_string().as_bytes()).to_vec();
    sqlx::query(
        "WITH receipt AS (\
            INSERT INTO app.project_view_receipts (project_id, viewer_hash, expires_at) \
            VALUES ($1, $2, now() + interval '1 hour') \
            ON CONFLICT (project_id, viewer_hash) DO UPDATE \
            SET expires_at = EXCLUDED.expires_at \
            WHERE app.project_view_receipts.expires_at <= now() \
            RETURNING 1\
         ) \
         UPDATE app.projects SET views = views + 1 \
         WHERE id = $1 AND EXISTS (SELECT 1 FROM receipt)",
    )
    .bind(project_id)
    .bind(viewer_hash)
    .execute(pool)
    .await?;
    Ok(())
}

fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .and_then(|value| value.parse().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
        })
}

async fn viewing_enabled(pool: &PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(\
            (SELECT lower(value #>> '{}') = 'true' FROM app.runtime_config WHERE key = 'viewingEnabled'),\
            true\
        )",
    )
    .fetch_one(pool)
    .await
}

fn binary_response(bytes: Vec<u8>, content_type: &str, cache_control: Option<&str>) -> Response {
    let mut response = Response::new(Body::from(bytes));
    let content_type = HeaderValue::from_str(content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    if let Some(cache_control) = cache_control
        && let Ok(value) = HeaderValue::from_str(cache_control)
    {
        response.headers_mut().insert(header::CACHE_CONTROL, value);
    }
    response
}

fn project_page(
    project_id: &str,
    title: &str,
    instructions: &str,
    notes: &str,
    author: &str,
) -> String {
    let mut thumbnail =
        reqwest::Url::parse("https://api.patternyard.dev/api/v1/projects/getproject")
            .expect("static project thumbnail URL");
    thumbnail
        .query_pairs_mut()
        .append_pair("projectID", project_id)
        .append_pair("requestType", "thumbnail");
    let mut studio = reqwest::Url::parse("https://studio.patternyard.dev")
        .expect("static PatternYard Studio URL");
    studio.set_fragment(Some(project_id));
    let description = if notes.is_empty() {
        instructions
    } else {
        notes
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta property=\"og:title\" content=\"{}\"><meta name=\"twitter:title\" content=\"{}\"><meta name=\"author\" content=\"{}\"><meta property=\"og:description\" content=\"{}\"><meta name=\"description\" content=\"{}\"><meta property=\"twitter:description\" content=\"{}\"><meta property=\"og:image\" content=\"{}\"><meta name=\"twitter:card\" content=\"summary_large_image\"><meta http-equiv=\"refresh\" content=\"0;url={}\"><title>PatternYard - {}</title></head><body><main><p>Opening this project in PatternYard Studio.</p><p><a href=\"{}\">Open project</a></p></main></body></html>",
        escape_html(title),
        escape_html(title),
        escape_html(author),
        escape_html(description),
        escape_html(description),
        escape_html(description),
        escape_html(thumbnail.as_str()),
        escape_html(studio.as_str()),
        escape_html(title),
        escape_html(studio.as_str()),
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[allow(clippy::too_many_arguments)]
async fn fetch_projects(
    pool: &PgPool,
    search: Option<&str>,
    remix_of: Option<&str>,
    featured_only: bool,
    order: ProjectOrder,
    ascending: bool,
    page: i64,
    page_size: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    fetch_projects_by_query(
        pool,
        None,
        search,
        remix_of,
        featured_only,
        order,
        ascending,
        page,
        page_size,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn fetch_projects_by_query(
    pool: &PgPool,
    project_id: Option<&str>,
    search: Option<&str>,
    remix_of: Option<&str>,
    featured_only: bool,
    order: ProjectOrder,
    ascending: bool,
    page: i64,
    page_size: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut builder = QueryBuilder::new(
        "SELECT jsonb_build_object(\
            'id', p.id, \
            'title', p.title, \
            'author', jsonb_build_object('id', u.id, 'username', u.username), \
            'instructions', p.instructions, \
            'notes', p.notes, \
            'rating', p.rating, \
            'public', p.is_public, \
            'featured', p.featured, \
            'softRejected', p.soft_rejected, \
            'hardReject', p.hard_rejected, \
            'noFeature', p.no_feature, \
            'modMessage', p.moderation_message, \
            'loves', p.loves, \
            'votes', p.votes, \
            'views', p.views, \
            'impressions', p.impressions, \
            'date', floor(extract(epoch FROM p.created_at) * 1000)::bigint, \
            'lastUpdate', floor(extract(epoch FROM p.updated_at) * 1000)::bigint, \
            'remix', p.remix_of_id, \
            'fromDonator', 'donator' = ANY(u.badges)\
        ) \
        FROM app.projects p \
        JOIN app.users u ON u.id = p.author_id \
        WHERE p.is_public = true AND NOT p.soft_rejected AND NOT p.hard_rejected",
    );

    if let Some(project_id) = project_id {
        builder.push(" AND p.id = ").push_bind(project_id);
    }
    if let Some(search) = search {
        let pattern = format!("%{search}%");
        builder
            .push(" AND (p.title ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR p.instructions ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR p.notes ILIKE ")
            .push_bind(pattern)
            .push(")");
    }
    if let Some(remix_of) = remix_of {
        builder.push(" AND p.remix_of_id = ").push_bind(remix_of);
    }
    if featured_only {
        builder.push(" AND p.featured = true");
    }

    if matches!(order, ProjectOrder::Random) {
        builder.push(" ORDER BY random()");
    } else {
        builder.push(" ORDER BY ");
        builder.push(match order {
            ProjectOrder::LastUpdate => "p.updated_at",
            ProjectOrder::UploadDate => "p.created_at",
            ProjectOrder::Views => "p.views",
            ProjectOrder::Loves => "p.loves",
            ProjectOrder::Votes => "p.votes",
            ProjectOrder::Random => unreachable!(),
        });
        builder.push(if ascending { " ASC" } else { " DESC" });
        builder.push(", p.id ASC");
    }

    builder
        .push(" LIMIT ")
        .push_bind(page_size.clamp(0, MAX_PAGE_SIZE))
        .push(" OFFSET ")
        .push_bind(page.saturating_mul(page_size));

    builder.build_query_scalar::<Value>().fetch_all(pool).await
}

fn page(value: Option<i64>) -> i64 {
    value.unwrap_or(0).max(0)
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty() && value != "undefined")
}

fn respond_with_projects(result: Result<Vec<Value>, sqlx::Error>) -> Response {
    match result {
        Ok(projects) => Json(projects).into_response(),
        Err(error) => query_failed(error),
    }
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "public project query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_is_never_negative() {
        assert_eq!(page(None), 0);
        assert_eq!(page(Some(-3)), 0);
        assert_eq!(page(Some(4)), 4);
    }

    #[test]
    fn missing_query_values_are_rejected() {
        assert_eq!(non_empty(None), None);
        assert_eq!(non_empty(Some(String::new())), None);
        assert_eq!(non_empty(Some("undefined".into())), None);
        assert_eq!(non_empty(Some("42".into())), Some("42".into()));
    }

    #[test]
    fn private_blob_urls_are_store_scoped_and_path_checked() {
        let url = private_blob_url("vercel_blob_rw_store123_secret", "projects/42")
            .expect("valid private Blob URL");
        assert_eq!(
            url.as_str(),
            "https://store123.private.blob.vercel-storage.com/projects/42"
        );
        assert!(!url.as_str().contains("penguinmod.com"));
        assert!(private_blob_url("vercel_blob_rw_bad.example.com_secret", "projects/42").is_none());
        assert!(private_blob_url("vercel_blob_rw_store123_secret", "../secret").is_none());
    }

    #[test]
    fn wrapper_buffers_preserve_node_json_shape() {
        let value = serde_json::to_value(LegacyBuffer {
            kind: "Buffer",
            data: vec![1, 2, 3],
        })
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({ "type": "Buffer", "data": [1, 2, 3] })
        );
    }

    #[test]
    fn project_pages_escape_metadata_and_stay_on_patternyard() {
        let page = project_page("42", "<Build>", "Try it", "Notes", "A & B");
        assert!(page.contains("&lt;Build&gt;"));
        assert!(page.contains("A &amp; B"));
        assert!(page.contains("api.patternyard.dev"));
        assert!(page.contains("studio.patternyard.dev/#42"));
        assert!(!page.contains("penguinmod.com"));
    }
}
