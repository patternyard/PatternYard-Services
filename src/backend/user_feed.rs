use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_FEED_SIZE: i64 = 20;
const MAX_FEED_SIZE: i64 = 100;

#[derive(Deserialize)]
struct FeedQuery {
    token: Option<String>,
}

#[derive(Serialize)]
struct FeedResponse {
    feed: Vec<Value>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new().route("/api/v1/users/getmyfeed", get(get_my_feed))
}

async fn get_my_feed(State(database): State<Database>, Query(query): Query<FeedQuery>) -> Response {
    let token = query.token.unwrap_or_else(|| "undefined".to_owned());
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };

    match sqlx::query_scalar::<_, Value>(
        "SELECT jsonb_build_object(\
             'id', actor.id, \
             'username', actor.username, \
             'type', feed.activity_type, \
             'data', CASE \
                 WHEN feed.activity_type = 'follow' THEN \
                     jsonb_build_object('id', feed.target_id, 'username', target.username) \
                 WHEN feed.activity_type IN ('upload', 'remix') THEN \
                     jsonb_build_object('id', feed.target_id, 'name', project.title) \
                 ELSE to_jsonb(feed.target_id) \
             END, \
             'date', floor(extract(epoch FROM feed.created_at) * 1000)::bigint\
         ) \
         FROM app.user_feed feed \
         JOIN app.users actor ON actor.id = feed.user_id \
         JOIN app.follows following \
           ON following.follower_id = $1 \
          AND following.target_id = feed.user_id \
          AND following.active \
         LEFT JOIN app.users target \
           ON feed.activity_type = 'follow' AND target.id = feed.target_id \
         LEFT JOIN app.projects project \
           ON feed.activity_type IN ('upload', 'remix') AND project.id = feed.target_id \
         ORDER BY feed.created_at DESC, feed.id DESC \
         LIMIT $2",
    )
    .bind(user.id)
    .bind(feed_size())
    .fetch_all(pool)
    .await
    {
        Ok(feed) => Json(FeedResponse { feed }).into_response(),
        Err(error) => query_failed(error),
    }
}

fn feed_size() -> i64 {
    std::env::var("FEED_SIZE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_FEED_SIZE)
        .clamp(0, MAX_FEED_SIZE)
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "user feed query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_size_uses_safe_bounds() {
        assert_eq!(DEFAULT_FEED_SIZE, 20);
        assert_eq!(200_i64.clamp(0, MAX_FEED_SIZE), MAX_FEED_SIZE);
    }

    #[test]
    fn response_preserves_feed_wrapper() {
        let response =
            serde_json::to_value(FeedResponse { feed: Vec::new() }).expect("response serializes");
        assert_eq!(response, serde_json::json!({ "feed": [] }));
    }
}
