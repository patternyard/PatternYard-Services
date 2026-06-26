use crate::auth::{AuthenticatedUser, authenticate_token};
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

const PAGE_SIZE: i64 = 20;

#[derive(Deserialize, Default)]
struct MessageQuery {
    token: Option<String>,
    page: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct LegacyMessage {
    id: String,
    receiver: String,
    message: Value,
    disputable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    dispute: Option<String>,
    #[serde(rename = "projectID", skip_serializing_if = "Option::is_none")]
    project_id: Option<String>,
    read: bool,
    date: i64,
}

#[derive(Serialize)]
struct MessagesResponse {
    messages: Vec<LegacyMessage>,
}

#[derive(Serialize)]
struct CountResponse {
    count: i64,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/users/getmessages", get(get_messages))
        .route("/api/v1/users/getunreadmessages", get(get_unread_messages))
        .route("/api/v1/users/getmessagecount", get(get_message_count))
        .route(
            "/api/v1/users/getunreadmessagecount",
            get(get_unread_message_count),
        )
}

async fn get_messages(
    State(database): State<Database>,
    Query(query): Query<MessageQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, query.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let page = query.page.unwrap_or(0).max(0);

    match fetch_messages(pool, &user.id, page, false).await {
        Ok(messages) => Json(MessagesResponse { messages }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_unread_messages(
    State(database): State<Database>,
    Query(query): Query<MessageQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, query.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let page = query.page.unwrap_or(0).max(0);

    match fetch_unread_messages(pool, &user.id, page).await {
        Ok(messages) => Json(MessagesResponse { messages }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_message_count(
    State(database): State<Database>,
    Query(query): Query<MessageQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, query.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    match message_count(pool, &user.id, false).await {
        Ok(count) => Json(CountResponse { count }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_unread_message_count(
    State(database): State<Database>,
    Query(query): Query<MessageQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, query.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    match unread_count_with_policy_notices(pool, &user.id).await {
        Ok(count) => Json(CountResponse { count }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn authenticate(pool: &PgPool, token: Option<String>) -> Result<AuthenticatedUser, Response> {
    let token = token.unwrap_or_else(|| "undefined".to_owned());
    match authenticate_token(pool, &token).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(api_error(StatusCode::BAD_REQUEST, "Reauthenticate")),
        Err(error) => Err(query_failed(error)),
    }
}

async fn fetch_unread_messages(
    pool: &PgPool,
    receiver_id: &str,
    page: i64,
) -> Result<Vec<LegacyMessage>, sqlx::Error> {
    fetch_messages(pool, receiver_id, page, true).await
}

async fn fetch_messages(
    pool: &PgPool,
    receiver_id: &str,
    page: i64,
    unread_only: bool,
) -> Result<Vec<LegacyMessage>, sqlx::Error> {
    sqlx::query_as::<_, LegacyMessage>(
        "SELECT id, receiver_id AS receiver, \
            CASE WHEN message IS JSON THEN message::jsonb ELSE to_jsonb(message) END AS message, \
            disputable, dispute, project_id, is_read AS read, \
            floor(extract(epoch FROM created_at) * 1000)::bigint AS date \
         FROM app.messages \
         WHERE receiver_id = $1 AND (NOT $2 OR NOT is_read) \
         ORDER BY created_at DESC, id DESC \
         LIMIT $3 OFFSET $4",
    )
    .bind(receiver_id)
    .bind(unread_only)
    .bind(PAGE_SIZE)
    .bind(page.saturating_mul(PAGE_SIZE))
    .fetch_all(pool)
    .await
}

async fn message_count(
    pool: &PgPool,
    receiver_id: &str,
    unread_only: bool,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*)::bigint FROM app.messages \
         WHERE receiver_id = $1 AND (NOT $2 OR NOT is_read)",
    )
    .bind(receiver_id)
    .bind(unread_only)
    .fetch_one(pool)
    .await
}

async fn unread_count_with_policy_notices(
    pool: &PgPool,
    receiver_id: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "SELECT \
            (SELECT count(*) FROM app.messages WHERE receiver_id = $1 AND NOT is_read) + \
            (SELECT count(*) FROM app.policy_versions version \
             JOIN app.users users ON users.id = $1 \
             WHERE CASE version.policy \
                WHEN 'privacy' THEN users.last_privacy_policy_read_at \
                WHEN 'terms' THEN users.last_terms_read_at \
                WHEN 'guidelines' THEN users.last_guidelines_read_at \
             END IS NULL \
             OR CASE version.policy \
                WHEN 'privacy' THEN users.last_privacy_policy_read_at \
                WHEN 'terms' THEN users.last_terms_read_at \
                WHEN 'guidelines' THEN users.last_guidelines_read_at \
             END < version.published_at)::bigint",
    )
    .bind(receiver_id)
    .fetch_one(pool)
    .await
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "message read query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_shape_preserves_legacy_keys() {
        let message = LegacyMessage {
            id: "message-1".to_owned(),
            receiver: "user-1".to_owned(),
            message: serde_json::json!({ "type": "notice" }),
            disputable: false,
            dispute: None,
            project_id: Some("project-1".to_owned()),
            read: false,
            date: 1,
        };

        assert_eq!(
            serde_json::to_value(message).expect("serializes"),
            serde_json::json!({
                "id": "message-1",
                "receiver": "user-1",
                "message": { "type": "notice" },
                "disputable": false,
                "projectID": "project-1",
                "read": false,
                "date": 1
            })
        );
    }

    #[test]
    fn count_shape_stays_numeric() {
        assert_eq!(
            serde_json::to_value(CountResponse { count: 3 }).expect("serializes"),
            serde_json::json!({ "count": 3 })
        );
    }
}
