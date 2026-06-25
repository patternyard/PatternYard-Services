use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_PAGE_SIZE: i64 = 20;
const MAX_PAGE: i64 = 10_000;

#[derive(Deserialize)]
struct SearchUsersQuery {
    query: Option<String>,
    page: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct PublicUser {
    id: String,
    username: String,
    real_username: String,
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct PublicStats {
    user_count: i64,
    banned_count: i64,
    project_count: i64,
    remix_count: i64,
    featured_count: i64,
    total_views: i64,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/projects/searchusers", get(search_users))
        .route("/api/v1/misc/getStats", get(get_stats))
        .route(
            "/api/v1/misc/getLastPolicyUpdate",
            get(get_last_policy_update),
        )
}

async fn search_users(
    State(database): State<Database>,
    Query(query): Query<SearchUsersQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let page = parse_page(query.page);
    let search = format!("%{}%", query.query.unwrap_or_default());

    match sqlx::query_as::<_, PublicUser>(
        "SELECT id, username::text AS username, display_username AS real_username \
         FROM app.users \
         WHERE NOT permanently_banned AND username::text ILIKE $1 \
         ORDER BY follower_count DESC, username ASC \
         LIMIT $2 OFFSET $3",
    )
    .bind(search)
    .bind(DEFAULT_PAGE_SIZE)
    .bind(page * DEFAULT_PAGE_SIZE)
    .fetch_all(pool)
    .await
    {
        Ok(users) => Json(users).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_stats(State(database): State<Database>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_as::<_, PublicStats>(
        "SELECT \
            (SELECT count(*) FROM app.users WHERE NOT permanently_banned) AS user_count, \
            (SELECT count(*) FROM app.users WHERE permanently_banned OR unban_at > now()) AS banned_count, \
            (SELECT count(*) FROM app.projects) AS project_count, \
            (SELECT count(*) FROM app.projects WHERE remix_of_id IS NOT NULL) AS remix_count, \
            (SELECT count(*) FROM app.projects WHERE featured) AS featured_count, \
            (SELECT COALESCE(sum(views), 0) FROM app.projects) AS total_views",
    )
    .fetch_one(pool)
    .await
    {
        Ok(stats) => Json(stats).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_last_policy_update(State(database): State<Database>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, Value>(
        "SELECT COALESCE(\
            jsonb_object_agg(\
                CASE policy \
                    WHEN 'privacy' THEN 'privacyPolicy' \
                    WHEN 'terms' THEN 'TOS' \
                    ELSE policy \
                END,\
                floor(extract(epoch FROM published_at) * 1000)::bigint\
            ),\
            '{}'::jsonb\
        ) FROM app.policy_versions",
    )
    .fetch_one(pool)
    .await
    {
        Ok(versions) => Json(versions).into_response(),
        Err(error) => query_failed(error),
    }
}

fn parse_page(page: Option<String>) -> i64 {
    page.and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
        .clamp(0, MAX_PAGE)
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "public discovery query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_parser_matches_legacy_non_negative_behavior() {
        assert_eq!(parse_page(None), 0);
        assert_eq!(parse_page(Some("invalid".into())), 0);
        assert_eq!(parse_page(Some("-3".into())), 0);
        assert_eq!(parse_page(Some("4".into())), 4);
        assert_eq!(parse_page(Some("999999".into())), MAX_PAGE);
    }
}
