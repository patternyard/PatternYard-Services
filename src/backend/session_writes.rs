use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize, Default)]
struct LogoutBody {
    token: Option<Value>,
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
    Router::new().route("/api/v1/users/logout", post(logout))
}

async fn logout(State(database): State<Database>, Json(body): Json<LogoutBody>) -> Response {
    let token = legacy_json_string(body.token);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };

    match sqlx::query(
        "UPDATE app.sessions SET revoked_at = now() \
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user.id)
    .execute(pool)
    .await
    {
        Ok(_) => Json(SuccessResponse { success: true }).into_response(),
        Err(error) => query_failed(error),
    }
}

fn legacy_json_string(value: Option<Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::String(value)) => value,
        Some(Value::Null) => "null".to_owned(),
        Some(value) => value.to_string(),
    }
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "session write query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn logout_token_matches_legacy_string_coercion() {
        assert_eq!(legacy_json_string(None), "undefined");
        assert_eq!(legacy_json_string(Some(json!(null))), "null");
        assert_eq!(legacy_json_string(Some(json!(123))), "123");
    }

    #[test]
    fn success_response_preserves_legacy_shape() {
        assert_eq!(
            serde_json::to_value(SuccessResponse { success: true }).expect("serializes"),
            json!({ "success": true })
        );
    }
}
