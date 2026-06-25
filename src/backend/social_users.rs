use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, QueryBuilder};

const DEFAULT_PAGE_SIZE: i64 = 20;
const MAX_PAGE: i64 = i32::MAX as i64;

#[derive(Deserialize)]
struct UsernameQuery {
    username: Option<String>,
}

#[derive(Deserialize)]
struct RelationshipQuery {
    username: Option<String>,
    target: Option<String>,
}

#[derive(Deserialize)]
struct FollowersQuery {
    username: Option<String>,
    page: Option<f64>,
}

#[derive(Deserialize)]
struct AuthTargetQuery {
    token: Option<String>,
    target: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct FollowerSummary {
    id: String,
    username: String,
    banned: bool,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/users/meta/getfollowers", get(get_followers))
        .route("/api/v1/users/isfollowing", get(is_following))
        .route("/api/v1/users/isBanned", get(is_banned))
        .route("/api/v1/users/hasblocked", get(has_blocked))
        .route("/api/v1/users/isadmin", get(is_admin))
        .route("/api/v1/users/ismod", get(is_moderator))
}

async fn get_followers(
    State(database): State<Database>,
    Query(query): Query<FollowersQuery>,
) -> Response {
    let username = legacy_username(query.username);
    let page = legacy_page(query.page);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    let target_id = match user_id(pool, &username).await {
        Ok(Some(id)) => id,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "User not found"),
        Err(error) => return query_failed(error),
    };

    let mut builder = QueryBuilder::new(
        "SELECT u.id, u.username::text AS username, u.permanently_banned AS banned \
         FROM app.follows f \
         JOIN app.users u ON u.id = f.follower_id \
         WHERE f.target_id = ",
    );
    builder
        .push_bind(target_id)
        .push(
            " AND f.active AND NOT u.permanently_banned \
               ORDER BY f.updated_at DESC, u.id \
               LIMIT ",
        )
        .push_bind(DEFAULT_PAGE_SIZE)
        .push(" OFFSET ")
        .push_bind(page.saturating_mul(DEFAULT_PAGE_SIZE));

    match builder
        .build_query_as::<FollowerSummary>()
        .fetch_all(pool)
        .await
    {
        Ok(followers) => Json(followers).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn is_following(
    State(database): State<Database>,
    Query(query): Query<RelationshipQuery>,
) -> Response {
    let username = legacy_username(query.username);
    let target = legacy_username(query.target);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    let follower_id = match user_id(pool, &username).await {
        Ok(Some(id)) => id,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "NotFound"),
        Err(error) => return query_failed(error),
    };
    let target_id = match user_id(pool, &target).await {
        Ok(Some(id)) => id,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "NotFound"),
        Err(error) => return query_failed(error),
    };

    match follows(pool, &follower_id, &target_id).await {
        Ok(following) => Json(json!({ "following": following })).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn is_banned(
    State(database): State<Database>,
    Query(query): Query<UsernameQuery>,
) -> Response {
    let username = legacy_username(query.username);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, bool>(
        "SELECT permanently_banned OR unban_at > now() FROM app.users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    {
        Ok(banned) => Json(json!({ "isBanned": banned })).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn has_blocked(
    State(database): State<Database>,
    Query(query): Query<AuthTargetQuery>,
) -> Response {
    let token = legacy_string(query.token);
    let target = legacy_username(query.target);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };
    let target_id = match user_id(pool, &target).await {
        Ok(Some(id)) => id,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "Target not found"),
        Err(error) => return query_failed(error),
    };

    match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM app.blocks WHERE blocker_id = $1 AND blocked_id = $2)",
    )
    .bind(user.id)
    .bind(target_id)
    .fetch_one(pool)
    .await
    {
        Ok(has_blocked) => Json(json!({ "has_blocked": has_blocked })).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn is_admin(
    State(database): State<Database>,
    Query(query): Query<AuthTargetQuery>,
) -> Response {
    get_staff_state(database, query, StaffRole::Admin).await
}

async fn is_moderator(
    State(database): State<Database>,
    Query(query): Query<AuthTargetQuery>,
) -> Response {
    get_staff_state(database, query, StaffRole::Moderator).await
}

#[derive(Clone, Copy)]
enum StaffRole {
    Admin,
    Moderator,
}

async fn get_staff_state(database: Database, query: AuthTargetQuery, role: StaffRole) -> Response {
    let token = legacy_string(query.token);
    let target = legacy_username(query.target);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };
    if !user.admin {
        return api_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    }

    let column = match role {
        StaffRole::Admin => "admin",
        StaffRole::Moderator => "moderator",
    };
    let mut builder = QueryBuilder::new("SELECT COALESCE((SELECT ");
    builder
        .push(column)
        .push(" FROM app.users WHERE username = ")
        .push_bind(target)
        .push("), false)");

    match builder.build_query_scalar::<bool>().fetch_one(pool).await {
        Ok(value) => match role {
            StaffRole::Admin => Json(json!({ "isAdmin": value })).into_response(),
            StaffRole::Moderator => Json(json!({ "isMod": value })).into_response(),
        },
        Err(error) => query_failed(error),
    }
}

async fn user_id(pool: &PgPool, username: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>("SELECT id FROM app.users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
}

async fn follows(pool: &PgPool, follower_id: &str, target_id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(\
            SELECT 1 FROM app.follows \
            WHERE follower_id = $1 AND target_id = $2 AND active\
        )",
    )
    .bind(follower_id)
    .bind(target_id)
    .fetch_one(pool)
    .await
}

fn legacy_string(value: Option<String>) -> String {
    value.unwrap_or_else(|| "undefined".to_owned())
}

fn legacy_username(value: Option<String>) -> String {
    legacy_string(value).to_lowercase()
}

fn legacy_page(value: Option<f64>) -> i64 {
    let value = value.unwrap_or(0.0);
    if !value.is_finite() || value <= 0.0 {
        0
    } else {
        value.floor().min(MAX_PAGE as f64) as i64
    }
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "social user query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_parsing_matches_non_negative_legacy_pages() {
        assert_eq!(legacy_page(None), 0);
        assert_eq!(legacy_page(Some(-2.0)), 0);
        assert_eq!(legacy_page(Some(2.9)), 2);
        assert_eq!(legacy_page(Some(f64::NAN)), 0);
    }

    #[test]
    fn missing_ban_state_serializes_as_null() {
        assert_eq!(
            json!({ "isBanned": Option::<bool>::None }),
            json!({ "isBanned": null })
        );
    }
}
