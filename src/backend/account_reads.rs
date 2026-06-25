use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct TargetQuery {
    target: Option<String>,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(Serialize)]
struct CustomizationResponse {
    customization: String,
}

#[derive(sqlx::FromRow)]
struct CustomizationRecord {
    badges: Vec<String>,
    disabled: Option<bool>,
    settings: Option<Value>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/users/tokenlogin", get(token_login))
        .route(
            "/api/v1/users/customization/getCustomization",
            get(get_customization),
        )
}

async fn token_login(
    State(database): State<Database>,
    Query(query): Query<TokenQuery>,
) -> Response {
    let token = legacy_string(query.token);
    if token.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing token");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match authenticate_token(pool, &token).await {
        Ok(Some(_)) => Json(SuccessResponse { success: true }).into_response(),
        Ok(None) => api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => query_failed(error),
    }
}

async fn get_customization(
    State(database): State<Database>,
    Query(query): Query<TargetQuery>,
) -> Response {
    let target = legacy_string(query.target).to_lowercase();
    if target.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing target");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_as::<_, CustomizationRecord>(
        "SELECT u.badges, c.disabled, c.settings \
         FROM app.users u \
         LEFT JOIN app.account_customizations c ON c.user_id = u.id \
         WHERE u.username = $1",
    )
    .bind(target)
    .fetch_optional(pool)
    .await
    {
        Ok(None) => api_error(StatusCode::NOT_FOUND, "User does not exist"),
        Ok(Some(record)) if !record.badges.iter().any(|badge| badge == "donator") => {
            api_error(StatusCode::BAD_REQUEST, "NotDonator")
        }
        Ok(Some(record)) => {
            let customization = if record.disabled.unwrap_or(false) {
                "{}".to_owned()
            } else {
                record
                    .settings
                    .map(|settings| settings.to_string())
                    .unwrap_or_else(|| "{}".to_owned())
            };
            Json(CustomizationResponse { customization }).into_response()
        }
        Err(error) => query_failed(error),
    }
}

fn legacy_string(value: Option<String>) -> String {
    value.unwrap_or_else(|| "undefined".to_owned())
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "account read query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_legacy_string_coercion() {
        assert_eq!(legacy_string(None), "undefined");
        assert_eq!(legacy_string(Some(String::new())), "");
    }

    #[test]
    fn customization_remains_stringified_json() {
        let response = CustomizationResponse {
            customization: serde_json::json!({ "theme": "calm" }).to_string(),
        };
        assert_eq!(
            serde_json::to_value(response).expect("serializes"),
            serde_json::json!({ "customization": "{\"theme\":\"calm\"}" })
        );
    }
}
