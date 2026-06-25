use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarkMessageBody {
    token: Option<String>,
    #[serde(rename = "messageID")]
    message_id: Option<String>,
}

#[derive(Deserialize)]
struct TokenBody {
    token: Option<String>,
}

#[derive(Serialize)]
struct SuccessBody {
    success: bool,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route(
            "/api/v1/users/markmessageasread",
            post(mark_message_as_read),
        )
        .route(
            "/api/v1/users/markallmessagesasread",
            post(mark_all_messages_as_read),
        )
}

async fn mark_message_as_read(
    State(database): State<Database>,
    Json(body): Json<MarkMessageBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user_id = match authenticate(pool, body.token).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let message_id = body.message_id.unwrap_or_else(|| "undefined".to_owned());

    match sqlx::query(
        "UPDATE app.messages SET is_read = TRUE \
         WHERE id = $1 AND receiver_id = $2",
    )
    .bind(message_id)
    .bind(user_id)
    .execute(pool)
    .await
    {
        Ok(result) if result.rows_affected() == 1 => {
            Json(SuccessBody { success: true }).into_response()
        }
        Ok(_) => api_error(StatusCode::BAD_REQUEST, "Invalid message ID"),
        Err(error) => query_failed(error),
    }
}

async fn mark_all_messages_as_read(
    State(database): State<Database>,
    Json(body): Json<TokenBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user_id = match authenticate(pool, body.token).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };

    match sqlx::query("UPDATE app.messages SET is_read = TRUE WHERE receiver_id = $1")
        .bind(user_id)
        .execute(pool)
        .await
    {
        Ok(_) => Json(SuccessBody { success: true }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn authenticate(pool: &PgPool, token: Option<String>) -> Result<String, Response> {
    let token = token.unwrap_or_else(|| "undefined".to_owned());
    match authenticate_token(pool, &token).await {
        Ok(Some(user)) => Ok(user.id),
        Ok(None) => Err(api_error(StatusCode::BAD_REQUEST, "Reauthenticate")),
        Err(error) => Err(query_failed(error)),
    }
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "message mutation query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, error: &'static str) -> Response {
    (status, Json(ErrorBody { error })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_body_preserves_legacy_message_id_name() {
        let body: MarkMessageBody = serde_json::from_value(serde_json::json!({
            "token": "session",
            "messageID": "message-1"
        }))
        .expect("valid mark body");
        assert_eq!(body.message_id.as_deref(), Some("message-1"));
    }

    #[test]
    fn success_contract_is_boolean() {
        assert_eq!(
            serde_json::to_value(SuccessBody { success: true }).expect("serializable"),
            serde_json::json!({ "success": true })
        );
    }
}
