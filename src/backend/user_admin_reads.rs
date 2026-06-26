use crate::auth::{AuthenticatedUser, authenticate_token};
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgPool;

const PAGE_SIZE: i64 = 20;

#[derive(Deserialize, Default)]
struct AdminQuery {
    token: Option<String>,
    target: Option<String>,
    page: Option<i64>,
}

#[derive(Serialize)]
struct SuccessList<T> {
    users: T,
}

#[derive(Serialize)]
struct IpsResponse {
    ips: Vec<String>,
}

#[derive(Serialize)]
struct AltsResponse {
    alts: Vec<String>,
}

#[derive(Serialize)]
struct EmailResponse {
    email: String,
}

#[derive(Serialize)]
struct StatsResponse {
    stats: Value,
}

#[derive(Serialize)]
struct ItemsResponse {
    items: Vec<Value>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route(
            "/api/v1/users/getAllAccountsWithIP",
            get(get_accounts_with_ip),
        )
        .route("/api/v1/users/getAllIPs", get(get_all_ips))
        .route("/api/v1/users/getAlts", get(get_alts))
        .route("/api/v1/users/getemail", get(get_email))
        .route("/api/v1/users/getuserstats", get(get_user_stats))
        .route("/api/v1/users/getworstoffenders", get(get_worst_offenders))
}

async fn get_accounts_with_ip(
    State(database): State<Database>,
    Query(query): Query<AdminQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, query.token).await {
        return response;
    }
    let target = legacy_string(query.target);
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT DISTINCT u.id, u.display_username FROM app.logged_ips source \
         JOIN app.logged_ips related ON related.ip = source.ip \
         JOIN app.users u ON u.id = related.user_id \
         WHERE source.ip = $1::inet OR source.user_id IN \
           (SELECT id FROM app.users WHERE username = lower($1)::citext) \
         ORDER BY u.display_username",
    )
    .bind(target)
    .fetch_all(pool)
    .await;
    match rows {
        Ok(users) => Json(SuccessList {
            users: users
                .into_iter()
                .map(|(id, username)| json!({ "id": id, "username": username }))
                .collect::<Vec<_>>(),
        })
        .into_response(),
        Err(error) if is_invalid_ip(&error) => {
            Json(SuccessList::<Vec<Value>> { users: Vec::new() }).into_response()
        }
        Err(error) => query_failed(error),
    }
}

async fn get_all_ips(
    State(database): State<Database>,
    Query(query): Query<AdminQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, query.token).await {
        return response;
    }
    let target = legacy_username(query.target);
    let ips = sqlx::query_scalar::<_, String>(
        "SELECT host(ip) FROM app.logged_ips WHERE user_id = \
         (SELECT id FROM app.users WHERE username = $1) ORDER BY last_seen_at DESC NULLS LAST",
    )
    .bind(target)
    .fetch_all(pool)
    .await;
    match ips {
        Ok(ips) if !ips.is_empty() => Json(IpsResponse { ips }).into_response(),
        Ok(_) => api_error(StatusCode::NOT_FOUND, "User not found"),
        Err(error) => query_failed(error),
    }
}

async fn get_alts(State(database): State<Database>, Query(query): Query<AdminQuery>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_moderator(pool, query.token).await {
        return response;
    }
    let target = legacy_username(query.target);
    let alts = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT related_user.display_username FROM app.users target_user \
         JOIN app.logged_ips target_ip ON target_ip.user_id = target_user.id \
         JOIN app.logged_ips related_ip ON related_ip.ip = target_ip.ip \
         JOIN app.users related_user ON related_user.id = related_ip.user_id \
         WHERE target_user.username = $1 AND related_user.id <> target_user.id \
         ORDER BY related_user.display_username",
    )
    .bind(target)
    .fetch_all(pool)
    .await;
    match alts {
        Ok(alts) => Json(AltsResponse { alts }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_email(State(database): State<Database>, Query(query): Query<AdminQuery>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, query.token).await {
        return response;
    }
    let target = legacy_username(query.target);
    match sqlx::query_scalar::<_, String>(
        "SELECT details.email::text FROM app.users users JOIN app.user_private_details details \
         ON details.user_id = users.id WHERE users.username = $1 AND details.email IS NOT NULL",
    )
    .bind(target)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(email)) => Json(EmailResponse { email }).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "UserNotFound"),
        Err(error) => query_failed(error),
    }
}

async fn get_user_stats(
    State(database): State<Database>,
    Query(query): Query<AdminQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, query.token).await {
        return response;
    }
    let row = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "SELECT count(*)::bigint, \
         count(*) FILTER (WHERE first_login_at >= now() - interval '1 day')::bigint, \
         count(*) FILTER (WHERE first_login_at >= now() - interval '7 days')::bigint, \
         count(*) FILTER (WHERE first_login_at >= now() - interval '30 days')::bigint FROM app.users",
    )
    .fetch_one(pool)
    .await;
    match row {
        Ok((total, day, week, month)) => Json(StatsResponse {
            stats: json!({ "total": total, "day": day, "week": week, "month": month }),
        })
        .into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_worst_offenders(
    State(database): State<Database>,
    Query(query): Query<AdminQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, query.token).await {
        return response;
    }
    let page = query.page.unwrap_or(0).max(0);
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT users.id, users.display_username, count(DISTINCT related.user_id)::bigint AS accounts \
         FROM app.users users JOIN app.logged_ips own ON own.user_id = users.id \
         JOIN app.logged_ips related ON related.ip = own.ip \
         GROUP BY users.id, users.display_username HAVING count(DISTINCT related.user_id) > 1 \
         ORDER BY accounts DESC, users.display_username LIMIT $1 OFFSET $2",
    )
    .bind(PAGE_SIZE)
    .bind(page.saturating_mul(PAGE_SIZE))
    .fetch_all(pool)
    .await;
    match rows {
        Ok(rows) => Json(ItemsResponse { items: rows.into_iter().map(|(id, username, accounts)| json!({ "id": id, "username": username, "accounts": accounts })).collect() }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn authenticate(pool: &PgPool, token: Option<String>) -> Result<AuthenticatedUser, Response> {
    let token = legacy_string(token);
    match authenticate_token(pool, &token).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(api_error(StatusCode::BAD_REQUEST, "Reauthenticate")),
        Err(error) => Err(query_failed(error)),
    }
}

async fn require_admin(
    pool: &PgPool,
    token: Option<String>,
) -> Result<AuthenticatedUser, Response> {
    let user = authenticate(pool, token).await?;
    if user.admin {
        Ok(user)
    } else {
        Err(api_error(StatusCode::UNAUTHORIZED, "Unauthorized"))
    }
}

async fn require_moderator(
    pool: &PgPool,
    token: Option<String>,
) -> Result<AuthenticatedUser, Response> {
    let user = authenticate(pool, token).await?;
    if user.admin || user.moderator {
        Ok(user)
    } else {
        Err(api_error(StatusCode::FORBIDDEN, "Unauthorized"))
    }
}

fn legacy_string(value: Option<String>) -> String {
    value.unwrap_or_else(|| "undefined".to_owned())
}
fn legacy_username(value: Option<String>) -> String {
    legacy_string(value).to_lowercase()
}
fn is_invalid_ip(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.code().as_deref() == Some("22P02"))
}
fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}
fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "user admin read query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}
fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_response_shapes_preserve_legacy_wrappers() {
        assert_eq!(
            serde_json::to_value(IpsResponse {
                ips: vec!["127.0.0.1".into()]
            })
            .unwrap(),
            json!({ "ips": ["127.0.0.1"] })
        );
        assert_eq!(
            serde_json::to_value(AltsResponse {
                alts: vec!["Builder".into()]
            })
            .unwrap(),
            json!({ "alts": ["Builder"] })
        );
    }
}
