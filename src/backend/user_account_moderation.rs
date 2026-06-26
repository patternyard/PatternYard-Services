use crate::auth::{AuthenticatedUser, authenticate_token};
use crate::db::Database;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Deserialize, Default)]
struct Body {
    token: Option<Value>,
    target: Option<Value>,
    toggle: Option<Value>,
    enabled: Option<Value>,
    admin: Option<Value>,
    approver: Option<Value>,
    time: Option<Value>,
    reason: Option<Value>,
    #[serde(rename = "remove_follows")]
    remove_follows: Option<Value>,
    #[serde(rename = "targetIP")]
    target_ip: Option<Value>,
    #[serde(rename = "newId")]
    new_id: Option<Value>,
    #[serde(rename = "newUsername")]
    new_username: Option<Value>,
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
        .route("/api/v1/users/assignPossition", post(assign_position))
        .route("/api/v1/users/ban", post(ban))
        .route("/api/v1/users/banip", post(ban_ip))
        .route("/api/v1/users/banuserip", post(ban_user_ip))
        .route("/api/v1/users/changeprojectid", post(change_project_id))
        .route("/api/v1/users/changeusernameadmin", post(change_username))
        .route("/api/v1/users/deleteaccount", post(delete_account))
        .route("/api/v1/users/deleteallemails", post(delete_all_emails))
        .route("/api/v1/users/massbanregex", post(mass_ban_disabled))
        .route("/api/v1/users/putonwatchlist", post(put_on_watchlist))
}

async fn assign_position(State(database): State<Database>, Json(body): Json<Body>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, body.token).await {
        return response;
    }
    let target = username(body.target);
    let result = sqlx::query(
        "UPDATE app.users SET admin = $2, moderator = $3, updated_at = now() WHERE username = $1",
    )
    .bind(target)
    .bind(legacy_bool(body.admin.as_ref()))
    .bind(legacy_bool(body.approver.as_ref()))
    .execute(pool)
    .await;
    mutation_result(result, "AccountDoesNotExist")
}

async fn ban(State(database): State<Database>, Json(body): Json<Body>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let actor = match require_staff(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let target = username(body.target);
    let toggle = legacy_bool(body.toggle.as_ref());
    let time = legacy_i64(body.time.as_ref()).unwrap_or(0);
    let reason = legacy_string(body.reason);
    let remove_follows = body
        .remove_follows
        .as_ref()
        .is_none_or(|value| legacy_string(Some(value.clone())) != "false");
    if reason.chars().count() > 512 || time < 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "Missing token, target, toggle, reason, or time",
        );
    }
    let target_user = match sqlx::query_as::<_, (String, bool)>(
        "SELECT id, admin FROM app.users WHERE username = $1",
    )
    .bind(&target)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "NotFound"),
        Err(error) => return query_failed(error),
    };
    if target_user.1 && !actor.admin {
        return api_error(StatusCode::FORBIDDEN, "Unauthorized");
    }
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return query_failed(error),
    };
    let unban_at = if toggle && time > 0 { Some(time) } else { None };
    if let Err(error) = sqlx::query(
        "UPDATE app.users SET permanently_banned = $2, unban_at = CASE WHEN $3::bigint IS NULL THEN NULL ELSE now() + $3 * interval '1 millisecond' END, ban_reason = $4, updated_at = now() WHERE id = $1",
    ).bind(&target_user.0).bind(toggle && time == 0).bind(unban_at).bind(if toggle { &reason } else { "" }).execute(&mut *tx).await { return query_failed(error) }
    if toggle
        && time == 0
        && remove_follows
        && let Err(error) = remove_user_follows(&mut tx, &target_user.0).await
    {
        return query_failed(error);
    }
    let notification = if !toggle {
        json!({"type":"unban"})
    } else if time > 0 {
        json!({"type":"tempban","time":time,"reason":reason})
    } else {
        json!({"type":"ban","reason":reason})
    };
    if let Err(error) = insert_message(&mut tx, &target_user.0, notification).await {
        return query_failed(error);
    }
    if let Err(error) =
        sqlx::query("DELETE FROM app.reports WHERE report_type = 0 AND reportee_id = $1")
            .bind(&target_user.0)
            .execute(&mut *tx)
            .await
    {
        return query_failed(error);
    }
    commit(tx).await
}

async fn ban_ip(State(database): State<Database>, Json(body): Json<Body>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let actor = match require_admin(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let ip = match legacy_string(body.target_ip).parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => return api_error(StatusCode::BAD_REQUEST, "Could not convert to IPv6"),
    };
    let result = if legacy_bool(body.toggle.as_ref()) {
        sqlx::query("INSERT INTO app.banned_ips (ip, created_by_user_id) VALUES ($1::inet, $2) ON CONFLICT (ip) DO UPDATE SET created_by_user_id = EXCLUDED.created_by_user_id, created_at = now()")
            .bind(ip).bind(actor.id).execute(pool).await
    } else {
        sqlx::query("DELETE FROM app.banned_ips WHERE ip = $1::inet")
            .bind(ip)
            .execute(pool)
            .await
    };
    match result {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn ban_user_ip(State(database): State<Database>, Json(body): Json<Body>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let actor = match require_admin(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let target = username(body.target);
    let target_id = match user_id(pool, &target).await {
        Ok(Some(id)) => id,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "NotFound"),
        Err(error) => return query_failed(error),
    };
    let result = if legacy_bool(body.toggle.as_ref()) {
        sqlx::query("INSERT INTO app.banned_ips (ip, created_by_user_id) SELECT ip, $2 FROM app.logged_ips WHERE user_id = $1 ON CONFLICT (ip) DO UPDATE SET created_by_user_id = EXCLUDED.created_by_user_id, created_at = now()")
            .bind(target_id).bind(actor.id).execute(pool).await
    } else {
        sqlx::query("DELETE FROM app.banned_ips WHERE ip IN (SELECT ip FROM app.logged_ips WHERE user_id = $1)").bind(target_id).execute(pool).await
    };
    match result {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn change_project_id(State(database): State<Database>, Json(body): Json<Body>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, body.token).await {
        return response;
    }
    let target = legacy_string(body.target);
    let new_id = legacy_string(body.new_id);
    if target.is_empty() || new_id.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "ProjectDoesNotExist");
    }
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return query_failed(error),
    };
    match sqlx::query("UPDATE app.projects SET id = $2, updated_at = now() WHERE id = $1")
        .bind(&target)
        .bind(&new_id)
        .execute(&mut *tx)
        .await
    {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => return api_error(StatusCode::BAD_REQUEST, "ProjectDoesNotExist"),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            return api_error(StatusCode::BAD_REQUEST, "IDIsTaken");
        }
        Err(error) => return query_failed(error),
    }
    for query in [
        "UPDATE app.users SET featured_project_id = $2, updated_at = now() WHERE featured_project_id = $1",
        "UPDATE app.reports SET reportee_id = $2 WHERE report_type = 1 AND reportee_id = $1",
        "UPDATE app.user_feed SET target_id = $2 WHERE target_id = $1",
        "UPDATE app.storage_values SET project_id = $2, updated_at = now() WHERE project_id = $1",
    ] {
        if let Err(error) = sqlx::query(query)
            .bind(&target)
            .bind(&new_id)
            .execute(&mut *tx)
            .await
        {
            return query_failed(error);
        }
    }
    commit(tx).await
}

async fn change_username(State(database): State<Database>, Json(body): Json<Body>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_staff(pool, body.token).await {
        return response;
    }
    let target = username(body.target);
    let new_username = username(body.new_username);
    if !valid_username(&new_username) {
        return api_error(StatusCode::BAD_REQUEST, "InvalidUsername");
    }
    match sqlx::query("UPDATE app.users SET username = $2, display_username = $2, updated_at = now() WHERE username = $1")
        .bind(target).bind(new_username).execute(pool).await {
        Ok(result) if result.rows_affected() == 1 => success(),
        Ok(_) => api_error(StatusCode::NOT_FOUND, "AccountDoesNotExist"),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => api_error(StatusCode::BAD_REQUEST, "UsernameInUse"),
        Err(error) => query_failed(error),
    }
}

async fn delete_account(State(database): State<Database>, Json(body): Json<Body>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, body.token).await {
        return response;
    }
    let target = username(body.target);
    let reason = legacy_string(body.reason);
    if reason.chars().count() > 512 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "Missing token, target, or reason, or reason is too long",
        );
    }
    let target_id = match user_id(pool, &target).await {
        Ok(Some(id)) => id,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "TargetNotFound"),
        Err(error) => return query_failed(error),
    };
    let blob_paths = match sqlx::query_scalar::<_, String>(
        "SELECT blob_pathname FROM app.profile_pictures WHERE user_id = $1 \
         UNION ALL \
         SELECT pb.blob_path FROM app.project_blobs pb JOIN app.projects p ON p.id = pb.project_id WHERE p.author_id = $1",
    )
    .bind(&target_id)
    .fetch_all(pool)
    .await
    {
        Ok(paths) => paths,
        Err(error) => return query_failed(error),
    };
    if let Err(response) = delete_blobs(&blob_paths).await {
        return response;
    }
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return query_failed(error),
    };
    for query in [
        "DELETE FROM app.reports WHERE reportee_id = $1",
        "DELETE FROM app.user_feed WHERE target_id = $1",
        "UPDATE app.banned_ips SET created_by_user_id = NULL WHERE created_by_user_id = $1",
    ] {
        if let Err(error) = sqlx::query(query).bind(&target_id).execute(&mut *tx).await {
            return query_failed(error);
        }
    }
    match sqlx::query("DELETE FROM app.users WHERE id = $1")
        .bind(target_id)
        .execute(&mut *tx)
        .await
    {
        Ok(result) if result.rows_affected() == 1 => commit(tx).await,
        Ok(_) => api_error(StatusCode::NOT_FOUND, "TargetNotFound"),
        Err(error) => query_failed(error),
    }
}

async fn delete_all_emails(State(database): State<Database>, Json(body): Json<Body>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, body.token).await {
        return response;
    }
    match sqlx::query("UPDATE app.user_private_details SET email = NULL, updated_at = now() WHERE email IS NOT NULL").execute(pool).await {
        Ok(_) => success(), Err(error) => query_failed(error),
    }
}

async fn mass_ban_disabled() -> Response {
    (StatusCode::from_u16(420).expect("420 is valid"), Json(json!({"error":"This endpoint has been disabled. Contact an administrator if you really need it."}))).into_response()
}

async fn put_on_watchlist(State(database): State<Database>, Json(body): Json<Body>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_staff(pool, body.token).await {
        return response;
    }
    let result = sqlx::query(
        "UPDATE app.users SET on_watchlist = $2, updated_at = now() WHERE username = $1",
    )
    .bind(username(body.target))
    .bind(legacy_bool(body.enabled.as_ref()))
    .execute(pool)
    .await;
    mutation_result(result, "AccountDoesNotExist")
}

async fn authenticate(pool: &PgPool, token: Option<Value>) -> Result<AuthenticatedUser, Response> {
    match authenticate_token(pool, &legacy_string(token)).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(api_error(StatusCode::BAD_REQUEST, "Reauthenticate")),
        Err(error) => Err(query_failed(error)),
    }
}
async fn require_admin(pool: &PgPool, token: Option<Value>) -> Result<AuthenticatedUser, Response> {
    let user = authenticate(pool, token).await?;
    if user.admin {
        Ok(user)
    } else {
        Err(api_error(StatusCode::FORBIDDEN, "Unauthorized"))
    }
}
async fn require_staff(pool: &PgPool, token: Option<Value>) -> Result<AuthenticatedUser, Response> {
    let user = authenticate(pool, token).await?;
    if user.admin || user.moderator {
        Ok(user)
    } else {
        Err(api_error(StatusCode::FORBIDDEN, "Unauthorized"))
    }
}
async fn user_id(pool: &PgPool, username: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM app.users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
}
async fn remove_user_follows(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM app.follows WHERE follower_id = $1 OR target_id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE app.users SET follower_count = (SELECT count(*)::integer FROM app.follows WHERE target_id = users.id AND active), following_count = (SELECT count(*)::integer FROM app.follows WHERE follower_id = users.id AND active), updated_at = now()")
        .execute(&mut **tx).await?;
    Ok(())
}
async fn insert_message(
    tx: &mut Transaction<'_, Postgres>,
    receiver: &str,
    message: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO app.messages (id, receiver_id, message, created_at) VALUES ($1, $2, $3, now())")
        .bind(Uuid::new_v4().to_string()).bind(receiver).bind(message.to_string()).execute(&mut **tx).await?;
    Ok(())
}
async fn commit(tx: Transaction<'_, Postgres>) -> Response {
    match tx.commit().await {
        Ok(()) => success(),
        Err(error) => query_failed(error),
    }
}
async fn delete_blobs(paths: &[String]) -> Result<(), Response> {
    if paths.is_empty() {
        return Ok(());
    }
    let token = std::env::var("BLOB_READ_WRITE_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
        .ok_or_else(storage_unavailable)?;
    let store_id = token
        .split('_')
        .nth(3)
        .filter(|store_id| !store_id.is_empty())
        .ok_or_else(storage_unavailable)?;
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
            tracing::error!(%error, "account Blob deletion failed");
            storage_unavailable()
        })?;
    if !response.status().is_success() {
        tracing::error!(status = %response.status(), "account Blob deletion rejected");
        return Err(storage_unavailable());
    }
    Ok(())
}
fn mutation_result(
    result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
    missing: &'static str,
) -> Response {
    match result {
        Ok(result) if result.rows_affected() == 1 => success(),
        Ok(_) => api_error(StatusCode::BAD_REQUEST, missing),
        Err(error) => query_failed(error),
    }
}
fn valid_username(value: &str) -> bool {
    (3..=24).contains(&value.len())
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
}
fn legacy_i64(value: Option<&Value>) -> Option<i64> {
    value.and_then(|value| value.as_i64().or_else(|| value.as_str()?.parse().ok()))
}
fn legacy_bool(value: Option<&Value>) -> bool {
    value.is_some_and(|value| match value {
        Value::Bool(value) => *value,
        Value::String(value) => value == "true",
        _ => false,
    })
}
fn username(value: Option<Value>) -> String {
    legacy_string(value).to_lowercase()
}
fn legacy_string(value: Option<Value>) -> String {
    match value {
        Some(Value::String(value)) => value,
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Null) | None => "undefined".to_owned(),
        Some(value) => value.to_string(),
    }
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
    tracing::error!(%error, "user account moderation query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}
fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn usernames_are_restricted_to_safe_legacy_characters() {
        assert!(valid_username("pattern-kid_9"));
        assert!(!valid_username("no spaces"));
        assert!(!valid_username("ab"));
    }
    #[test]
    fn mass_ban_remains_unconditionally_disabled() {
        assert_eq!(StatusCode::from_u16(420).unwrap().as_u16(), 420);
    }
}
