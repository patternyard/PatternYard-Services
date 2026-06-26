use crate::auth::{AuthenticatedUser, authenticate_token};
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

const MAX_PROJECT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ASSET_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ModerationBody {
    token: Option<Value>,
    target: Option<Value>,
    message: Option<Value>,
    disputable: Option<Value>,
    #[serde(rename = "messageID")]
    message_id: Option<Value>,
    #[serde(rename = "disputeID")]
    dispute_id: Option<Value>,
    dispute: Option<Value>,
    project: Option<Value>,
    #[serde(rename = "projectID")]
    project_id: Option<Value>,
    toggle: Option<Value>,
    reason: Option<Value>,
}

#[derive(Deserialize, Default)]
struct DownloadQuery {
    token: Option<String>,
    project: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ProjectRecord {
    author_id: String,
    title: String,
    is_public: bool,
    soft_rejected: bool,
    hard_rejected: bool,
    featured: bool,
}

#[derive(sqlx::FromRow)]
struct MessageRecord {
    receiver_id: String,
    disputable: bool,
    project_id: Option<String>,
    dispute: Option<String>,
}

#[derive(sqlx::FromRow)]
struct BlobRecord {
    asset_name: String,
    blob_path: String,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
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
struct HardRejectDownload {
    project: LegacyBuffer,
    assets: Vec<LegacyAsset>,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route(
            "/api/v1/projects/deletemodmessage",
            post(delete_mod_message),
        )
        .route("/api/v1/projects/deletethumb", post(delete_thumbnail))
        .route("/api/v1/projects/dispute", post(dispute_message))
        .route(
            "/api/v1/projects/downloadHardReject",
            get(download_hard_reject),
        )
        .route("/api/v1/projects/fixprojectstats", post(fix_project_stats))
        .route(
            "/api/v1/projects/hardDeleteProject",
            post(hard_delete_project),
        )
        .route("/api/v1/projects/hardreject", post(hard_reject))
        .route("/api/v1/projects/manualfeature", post(manual_feature))
        .route("/api/v1/projects/modmessage", post(mod_message))
        .route("/api/v1/projects/modresponse", post(mod_response))
        .route("/api/v1/projects/restore", post(restore_project))
        .route(
            "/api/v1/projects/setCanBeFeatured",
            post(set_can_be_featured),
        )
        .route("/api/v1/projects/softreject", post(soft_reject))
        .route(
            "/api/v1/projects/toggleaccountcreation",
            post(toggle_account_creation),
        )
        .route("/api/v1/projects/toggleuploading", post(toggle_uploading))
        .route("/api/v1/projects/toggleviewing", post(toggle_viewing))
}

async fn delete_mod_message(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Some(response) = require_staff(&user) {
        return response;
    }
    let message_id = legacy_json_string(body.message_id);
    match sqlx::query("DELETE FROM app.messages WHERE id = $1")
        .bind(message_id)
        .execute(pool)
        .await
    {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn delete_thumbnail(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Some(response) = require_staff(&user) {
        return response;
    }
    let project_id = legacy_json_string(body.project_id);
    if let Err(response) = require_public_project(pool, &project_id).await {
        return response;
    }
    let paths = match blob_paths(pool, &project_id, Some("thumbnail")).await {
        Ok(paths) => paths,
        Err(error) => return query_failed(error),
    };
    if let Err(response) = delete_blobs(&paths).await {
        return response;
    }
    match sqlx::query("DELETE FROM app.project_blobs WHERE project_id = $1 AND kind = 'thumbnail'")
        .bind(project_id)
        .execute(pool)
        .await
    {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn dispute_message(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let message_id = legacy_json_string(body.message_id);
    let dispute = legacy_json_string(body.dispute);
    let message = match message_by_id(pool, &message_id).await {
        Ok(Some(message)) if message.receiver_id == user.id => message,
        Ok(Some(_)) | Ok(None) => return api_error(StatusCode::NOT_FOUND, "MessageNotFound"),
        Err(error) => return query_failed(error),
    };
    if !message.disputable {
        return api_error(StatusCode::BAD_REQUEST, "NotDisputable");
    }
    match sqlx::query("UPDATE app.messages SET dispute = $2, disputable = false WHERE id = $1 AND receiver_id = $3")
        .bind(message_id).bind(dispute).bind(user.id).execute(pool).await
    {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn download_hard_reject(
    State(database): State<Database>,
    Query(query): Query<DownloadQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let token = query.token.unwrap_or_else(|| "undefined".to_owned());
    let user = match authenticated_string(pool, &token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let project_id = query.project.unwrap_or_else(|| "undefined".to_owned());
    let project = match project_by_id(pool, &project_id).await {
        Ok(Some(project)) => project,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "ProjectNotFound"),
        Err(error) => return query_failed(error),
    };
    if !user.admin && user.id != project.author_id {
        return api_error(StatusCode::UNAUTHORIZED, "Invalid credentials");
    }
    if !project.hard_rejected {
        return api_error(StatusCode::BAD_REQUEST, "NotHardRejected");
    }
    let project_blob = match blob_record(pool, &project_id, "project", "").await {
        Ok(Some(blob)) => blob,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "ProjectNotFound"),
        Err(error) => return query_failed(error),
    };
    let bytes = match download_blob(&project_blob.blob_path, MAX_PROJECT_BYTES).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    let asset_records = match asset_records(pool, &project_id).await {
        Ok(records) => records,
        Err(error) => return query_failed(error),
    };
    let mut remaining = MAX_ASSET_BYTES;
    let mut assets = Vec::with_capacity(asset_records.len());
    for asset in asset_records {
        let asset_bytes = match download_blob(&asset.blob_path, remaining).await {
            Ok(bytes) => bytes,
            Err(response) => return response,
        };
        remaining = remaining.saturating_sub(asset_bytes.len() as u64);
        assets.push(LegacyAsset {
            id: asset.asset_name,
            buffer: LegacyBuffer {
                kind: "Buffer",
                data: asset_bytes,
            },
        });
    }
    Json(HardRejectDownload {
        project: LegacyBuffer {
            kind: "Buffer",
            data: bytes,
        },
        assets,
    })
    .into_response()
}

async fn fix_project_stats(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Some(response) = require_admin(&user) {
        return response;
    }
    let project_id = legacy_json_string(body.project_id);
    if let Err(response) = require_public_project(pool, &project_id).await {
        return response;
    }
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = sqlx::query(
        "DELETE FROM app.project_interactions interaction USING app.users users \
         WHERE interaction.user_id = users.id AND interaction.project_id = $1 \
         AND interaction.kind IN ('love', 'vote') \
         AND (users.permanently_banned OR (users.unban_at IS NOT NULL AND users.unban_at > now()))",
    )
    .bind(&project_id)
    .execute(&mut *tx)
    .await
    {
        return query_failed(error);
    }
    if let Err(error) = sqlx::query(
        "UPDATE app.projects SET \
         loves = (SELECT count(*) FROM app.project_interactions WHERE project_id = $1 AND kind = 'love'), \
         votes = (SELECT count(*) FROM app.project_interactions WHERE project_id = $1 AND kind = 'vote') \
         WHERE id = $1"
    ).bind(&project_id).execute(&mut *tx).await { return query_failed(error) }
    match tx.commit().await {
        Ok(()) => success(),
        Err(error) => query_failed(error),
    }
}

async fn hard_delete_project(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let project_id = legacy_json_string(body.project_id);
    let reason = legacy_json_string(body.reason);
    let project = match project_by_id(pool, &project_id).await {
        Ok(Some(project)) => project,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "Project not found"),
        Err(error) => return query_failed(error),
    };
    if project.author_id != user.id && !user.admin {
        return api_error(
            StatusCode::FORBIDDEN,
            "You are not authorized to delete this project",
        );
    }
    let paths = match blob_paths(pool, &project_id, None).await {
        Ok(paths) => paths,
        Err(error) => return query_failed(error),
    };
    if let Err(response) = delete_blobs(&paths).await {
        return response;
    }
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return query_failed(error),
    };
    if project.author_id != user.id {
        let message = json!({ "type": "delete", "title": project.title, "message": reason });
        if let Err(error) = insert_message(
            &mut tx,
            &project.author_id,
            message,
            false,
            Some(&project_id),
        )
        .await
        {
            return query_failed(error);
        }
    }
    if let Err(error) = sqlx::query("DELETE FROM app.projects WHERE id = $1")
        .bind(project_id)
        .execute(&mut *tx)
        .await
    {
        return query_failed(error);
    }
    match tx.commit().await {
        Ok(()) => success(),
        Err(error) => query_failed(error),
    }
}

async fn hard_reject(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    reject_project(database, body, true).await
}

async fn soft_reject(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    reject_project(database, body, false).await
}

async fn reject_project(database: Database, body: ModerationBody, hard: bool) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Some(response) = require_staff(&user) {
        return response;
    }
    let project_id = legacy_json_string(body.project);
    let message = legacy_json_string(body.message);
    let project = match project_by_id(pool, &project_id).await {
        Ok(Some(project)) => project,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "ProjectNotFound"),
        Err(error) => return query_failed(error),
    };
    if hard && project.hard_rejected {
        return api_error(StatusCode::BAD_REQUEST, "AlreadyHardRejected");
    }
    if !hard && project.soft_rejected {
        return api_error(StatusCode::BAD_REQUEST, "AlreadySoftRejected");
    }
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return query_failed(error),
    };
    let update = if hard {
        "UPDATE app.projects SET hard_rejected = true, hard_rejected_at = now(), updated_at = now() WHERE id = $1"
    } else {
        "UPDATE app.projects SET soft_rejected = true, updated_at = now() WHERE id = $1"
    };
    if let Err(error) = sqlx::query(update)
        .bind(&project_id)
        .execute(&mut *tx)
        .await
    {
        return query_failed(error);
    }
    let notification = if hard {
        json!({ "type": "reject", "message": message, "hardReject": true, "title": project.title })
    } else {
        json!({ "type": "reject", "message": message, "hardReject": false })
    };
    if let Err(error) = insert_message(
        &mut tx,
        &project.author_id,
        notification,
        true,
        Some(&project_id),
    )
    .await
    {
        return query_failed(error);
    }
    if let Err(error) =
        sqlx::query("DELETE FROM app.reports WHERE report_type = 1 AND reportee_id = $1")
            .bind(&project_id)
            .execute(&mut *tx)
            .await
    {
        return query_failed(error);
    }
    match tx.commit().await {
        Ok(()) => success(),
        Err(error) => query_failed(error),
    }
}

async fn restore_project(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Some(response) = require_staff(&user) {
        return response;
    }
    let project_id = legacy_json_string(body.project);
    let project = match project_by_id(pool, &project_id).await {
        Ok(Some(project)) if project.is_public => project,
        Ok(_) => return api_error(StatusCode::NOT_FOUND, "ProjectNotFound"),
        Err(error) => return query_failed(error),
    };
    if !project.soft_rejected {
        return api_error(StatusCode::BAD_REQUEST, "NotSoftRejected");
    }
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = sqlx::query(
        "UPDATE app.projects SET soft_rejected = false, updated_at = now() WHERE id = $1",
    )
    .bind(&project_id)
    .execute(&mut *tx)
    .await
    {
        return query_failed(error);
    }
    if let Err(error) = insert_message(
        &mut tx,
        &project.author_id,
        json!({ "type": "restored" }),
        false,
        Some(&project_id),
    )
    .await
    {
        return query_failed(error);
    }
    match tx.commit().await {
        Ok(()) => success(),
        Err(error) => query_failed(error),
    }
}

async fn mod_message(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Some(response) = require_staff(&user) {
        return response;
    }
    let target = legacy_json_string(body.target);
    let message = legacy_json_string(body.message);
    let disputable = legacy_json_bool(body.disputable);
    let target_id =
        match sqlx::query_scalar::<_, String>("SELECT id FROM app.users WHERE username = $1")
            .bind(target)
            .fetch_optional(pool)
            .await
        {
            Ok(Some(id)) => id,
            Ok(None) => return api_error(StatusCode::NOT_FOUND, "UserNotFound"),
            Err(error) => return query_failed(error),
        };
    match insert_message_pool(
        pool,
        &target_id,
        json!({ "type": "modMessage", "message": message }),
        disputable,
        None,
    )
    .await
    {
        Ok(()) => success(),
        Err(error) => query_failed(error),
    }
}

async fn mod_response(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Some(response) = require_staff(&user) {
        return response;
    }
    let dispute_id = legacy_json_string(body.dispute_id);
    let message = legacy_json_string(body.message);
    let dispute = match message_by_id(pool, &dispute_id).await {
        Ok(Some(dispute)) => dispute,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "MessageNotFound"),
        Err(error) => return query_failed(error),
    };
    if dispute.dispute.is_none() {
        return api_error(StatusCode::BAD_REQUEST, "NotDisputed");
    }
    match insert_message_pool(
        pool,
        &dispute.receiver_id,
        json!({ "type": "disputeResponse", "message": message }),
        true,
        dispute.project_id.as_deref(),
    )
    .await
    {
        Ok(()) => success(),
        Err(error) => query_failed(error),
    }
}

async fn set_can_be_featured(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Some(response) = require_admin(&user) {
        return response;
    }
    let project_id = legacy_json_string(body.project_id);
    if let Err(response) = require_public_project(pool, &project_id).await {
        return response;
    }
    let can_feature = legacy_json_bool(body.toggle);
    match sqlx::query("UPDATE app.projects SET no_feature = $2, updated_at = now() WHERE id = $1")
        .bind(project_id)
        .bind(!can_feature)
        .execute(pool)
        .await
    {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn manual_feature(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Some(response) = require_admin(&user) {
        return response;
    }
    let project_id = legacy_json_string(body.project_id);
    let toggle = legacy_json_bool(body.toggle);
    let project = match project_by_id(pool, &project_id).await {
        Ok(Some(project)) if project.is_public => project,
        Ok(_) => return api_error(StatusCode::NOT_FOUND, "Project not found"),
        Err(error) => return query_failed(error),
    };
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return query_failed(error),
    };
    if toggle && !project.featured {
        if let Err(error) = insert_message(
            &mut tx,
            &project.author_id,
            json!({ "type": "projectFeatured" }),
            false,
            Some(&project_id),
        )
        .await
        {
            return query_failed(error);
        }
        let badges = match sqlx::query_scalar::<_, Vec<String>>(
            "SELECT badges FROM app.users WHERE id = $1",
        )
        .bind(&project.author_id)
        .fetch_one(&mut *tx)
        .await
        {
            Ok(badges) => badges,
            Err(error) => return query_failed(error),
        };
        let badge = if !badges.iter().any(|badge| badge == "featured") {
            Some("featured")
        } else if !badges.iter().any(|badge| badge == "multifeature") {
            Some("multifeature")
        } else {
            None
        };
        if let Some(badge) = badge {
            if let Err(error) = sqlx::query("UPDATE app.users SET badges = array_append(badges, $2), updated_at = now() WHERE id = $1")
                .bind(&project.author_id).bind(badge).execute(&mut *tx).await { return query_failed(error) }
            if let Err(error) = insert_message(
                &mut tx,
                &project.author_id,
                json!({ "type": "newBadge", "badge": badge }),
                false,
                Some(&project_id),
            )
            .await
            {
                return query_failed(error);
            }
        }
    }
    if let Err(error) =
        sqlx::query("UPDATE app.projects SET featured = $2, updated_at = now() WHERE id = $1")
            .bind(&project_id)
            .bind(toggle)
            .execute(&mut *tx)
            .await
    {
        return query_failed(error);
    }
    match tx.commit().await {
        Ok(()) => success(),
        Err(error) => query_failed(error),
    }
}

async fn toggle_account_creation(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    toggle_runtime(database, body, "accountCreationEnabled").await
}

async fn toggle_uploading(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    toggle_runtime(database, body, "uploadingEnabled").await
}

async fn toggle_viewing(
    State(database): State<Database>,
    Json(body): Json<ModerationBody>,
) -> Response {
    toggle_runtime(database, body, "viewingEnabled").await
}

async fn toggle_runtime(database: Database, body: ModerationBody, key: &'static str) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticated(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Some(response) = require_admin(&user) {
        return response;
    }
    let toggle = legacy_json_bool(body.toggle);
    match sqlx::query(
        "INSERT INTO app.runtime_config (key, value, updated_at) VALUES ($1, to_jsonb($2), now()) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(key)
    .bind(toggle)
    .execute(pool)
    .await
    {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn authenticated(pool: &PgPool, token: Option<Value>) -> Result<AuthenticatedUser, Response> {
    authenticated_string(pool, &legacy_json_string(token)).await
}

async fn authenticated_string(pool: &PgPool, token: &str) -> Result<AuthenticatedUser, Response> {
    match authenticate_token(pool, token).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(api_error(StatusCode::UNAUTHORIZED, "Reauthenticate")),
        Err(error) => Err(query_failed(error)),
    }
}

fn require_staff(user: &AuthenticatedUser) -> Option<Response> {
    (!user.admin && !user.moderator)
        .then(|| api_error(StatusCode::UNAUTHORIZED, "Invalid credentials"))
}

fn require_admin(user: &AuthenticatedUser) -> Option<Response> {
    (!user.admin).then(|| api_error(StatusCode::UNAUTHORIZED, "Invalid credentials"))
}

async fn require_public_project(pool: &PgPool, project_id: &str) -> Result<(), Response> {
    match project_by_id(pool, project_id).await {
        Ok(Some(project)) if project.is_public => Ok(()),
        Ok(_) => Err(api_error(StatusCode::NOT_FOUND, "Project not found")),
        Err(error) => Err(query_failed(error)),
    }
}

async fn project_by_id(
    pool: &PgPool,
    project_id: &str,
) -> Result<Option<ProjectRecord>, sqlx::Error> {
    sqlx::query_as::<_, ProjectRecord>(
        "SELECT p.author_id, p.title, p.is_public, p.soft_rejected, p.hard_rejected, p.featured \
         FROM app.projects p WHERE p.id = $1",
    )
    .bind(project_id)
    .fetch_optional(pool)
    .await
}

async fn message_by_id(
    pool: &PgPool,
    message_id: &str,
) -> Result<Option<MessageRecord>, sqlx::Error> {
    sqlx::query_as::<_, MessageRecord>(
        "SELECT receiver_id, disputable, project_id, dispute FROM app.messages WHERE id = $1",
    )
    .bind(message_id)
    .fetch_optional(pool)
    .await
}

async fn insert_message(
    tx: &mut Transaction<'_, Postgres>,
    receiver_id: &str,
    message: Value,
    disputable: bool,
    project_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO app.messages (id, receiver_id, message, disputable, project_id, is_read, created_at) \
         VALUES ($1, $2, $3, $4, $5, false, now())"
    ).bind(Uuid::new_v4().to_string()).bind(receiver_id).bind(message.to_string())
        .bind(disputable).bind(project_id).execute(&mut **tx).await?;
    Ok(())
}

async fn insert_message_pool(
    pool: &PgPool,
    receiver_id: &str,
    message: Value,
    disputable: bool,
    project_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO app.messages (id, receiver_id, message, disputable, project_id, is_read, created_at) \
         VALUES ($1, $2, $3, $4, $5, false, now())"
    ).bind(Uuid::new_v4().to_string()).bind(receiver_id).bind(message.to_string())
        .bind(disputable).bind(project_id).execute(pool).await?;
    Ok(())
}

async fn blob_paths(
    pool: &PgPool,
    project_id: &str,
    kind: Option<&str>,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT blob_path FROM app.project_blobs WHERE project_id = $1 AND ($2::text IS NULL OR kind = $2) ORDER BY blob_path"
    ).bind(project_id).bind(kind).fetch_all(pool).await
}

async fn blob_record(
    pool: &PgPool,
    project_id: &str,
    kind: &str,
    asset_name: &str,
) -> Result<Option<BlobRecord>, sqlx::Error> {
    sqlx::query_as::<_, BlobRecord>(
        "SELECT asset_name, blob_path FROM app.project_blobs WHERE project_id = $1 AND kind = $2 AND asset_name = $3"
    ).bind(project_id).bind(kind).bind(asset_name).fetch_optional(pool).await
}

async fn asset_records(pool: &PgPool, project_id: &str) -> Result<Vec<BlobRecord>, sqlx::Error> {
    sqlx::query_as::<_, BlobRecord>(
        "SELECT asset_name, blob_path FROM app.project_blobs WHERE project_id = $1 AND kind = 'asset' ORDER BY asset_name"
    ).bind(project_id).fetch_all(pool).await
}

async fn delete_blobs(paths: &[String]) -> Result<(), Response> {
    if paths.is_empty() {
        return Ok(());
    }
    let token = blob_token().ok_or_else(storage_unavailable)?;
    let store_id = blob_store_id(&token).ok_or_else(storage_unavailable)?;
    let response = reqwest::Client::new()
        .post("https://vercel.com/api/blob/delete")
        .bearer_auth(&token)
        .header("x-api-version", "12")
        .header(
            "x-api-blob-request-id",
            format!("{store_id}:{}", Uuid::new_v4()),
        )
        .header("x-api-blob-request-attempt", "0")
        .json(&json!({ "urls": paths }))
        .send()
        .await
        .map_err(|error| {
            tracing::error!(%error, "Blob deletion failed");
            storage_unavailable()
        })?;
    if !response.status().is_success() {
        tracing::error!(status = %response.status(), "Blob deletion rejected");
        return Err(storage_unavailable());
    }
    Ok(())
}

async fn download_blob(pathname: &str, max_bytes: u64) -> Result<Vec<u8>, Response> {
    let token = blob_token().ok_or_else(storage_unavailable)?;
    let url = private_blob_url(&token, pathname).ok_or_else(storage_unavailable)?;
    let response = reqwest::Client::new()
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| {
            tracing::error!(%error, %pathname, "Blob download failed");
            storage_unavailable()
        })?;
    if !response.status().is_success() {
        return Err(storage_unavailable());
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
        tracing::error!(%error, %pathname, "Blob body read failed");
        storage_unavailable()
    })?;
    if bytes.len() as u64 > max_bytes {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Project file too large",
        ));
    }
    Ok(bytes.to_vec())
}

fn blob_token() -> Option<String> {
    std::env::var("BLOB_READ_WRITE_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
}

fn blob_store_id(token: &str) -> Option<&str> {
    let store_id = token.split('_').nth(3)?;
    (!store_id.is_empty()
        && store_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-'))
    .then_some(store_id)
}

fn private_blob_url(token: &str, pathname: &str) -> Option<reqwest::Url> {
    let store_id = blob_store_id(token)?;
    if pathname.is_empty()
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

fn legacy_json_string(value: Option<Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::String(value)) => value,
        Some(Value::Null) => "null".to_owned(),
        Some(value) => value.to_string(),
    }
}

fn legacy_json_bool(value: Option<Value>) -> bool {
    legacy_json_string(value) == "true"
}
fn success() -> Response {
    Json(SuccessResponse { success: true }).into_response()
}
fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}
fn storage_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "StorageUnavailable")
}
fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "project moderation query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}
fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moderation_body_preserves_legacy_names() {
        let body: ModerationBody = serde_json::from_value(json!({
            "token": "session", "projectID": "project-1", "messageID": "message-1",
            "disputeID": "dispute-1", "toggle": true
        }))
        .expect("valid moderation body");
        assert_eq!(legacy_json_string(body.project_id), "project-1");
        assert_eq!(legacy_json_string(body.message_id), "message-1");
        assert_eq!(legacy_json_string(body.dispute_id), "dispute-1");
        assert!(legacy_json_bool(body.toggle));
    }

    #[test]
    fn hard_reject_download_preserves_node_buffer_shape() {
        let response = HardRejectDownload {
            project: LegacyBuffer {
                kind: "Buffer",
                data: vec![1, 2],
            },
            assets: vec![LegacyAsset {
                id: "costume.png".to_owned(),
                buffer: LegacyBuffer {
                    kind: "Buffer",
                    data: vec![3],
                },
            }],
        };
        assert_eq!(
            serde_json::to_value(response).expect("serializes"),
            json!({
                "project": { "type": "Buffer", "data": [1, 2] },
                "assets": [{ "id": "costume.png", "buffer": { "type": "Buffer", "data": [3] } }]
            })
        );
    }

    #[test]
    fn private_blob_urls_reject_unsafe_paths() {
        assert!(private_blob_url("vercel_blob_rw_store123_secret", "projects/42").is_some());
        assert!(private_blob_url("vercel_blob_rw_store123_secret", "../secret").is_none());
    }
}
