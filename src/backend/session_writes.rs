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

#[derive(Deserialize, Default)]
struct PasswordLoginBody {
    username: Option<Value>,
    password: Option<Value>,
    captcha_token: Option<Value>,
}

#[derive(Deserialize, Default)]
struct ChangePasswordBody {
    token: Option<Value>,
    old_password: Option<Value>,
    new_password: Option<Value>,
}

#[derive(sqlx::FromRow)]
struct PasswordRecord {
    id: String,
    password_hash: String,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
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
        .route("/api/v1/users/logout", post(logout))
        .route("/api/v1/users/passwordLogin", post(password_login))
        .route("/api/v1/users/changePassword", post(change_password))
}

async fn password_login(
    State(database): State<Database>,
    Json(body): Json<PasswordLoginBody>,
) -> Response {
    let Some(username) = required_json_string(body.username).map(|value| value.to_lowercase())
    else {
        return api_error(StatusCode::BAD_REQUEST, "Missing username or password");
    };
    let Some(password) = required_json_string(body.password) else {
        return api_error(StatusCode::BAD_REQUEST, "Missing username or password");
    };
    let captcha_token = legacy_json_string(body.captcha_token);
    if let Err(response) = verify_captcha(&captcha_token).await {
        return response;
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let record = match sqlx::query_as::<_, PasswordRecord>(
        "SELECT id, password_hash FROM app.users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "InvalidCredentials"),
        Err(error) => return query_failed(error),
    };
    if record.password_hash.is_empty() || !verify_password(password, record.password_hash).await {
        return api_error(StatusCode::UNAUTHORIZED, "InvalidCredentials");
    }

    match create_session(pool, &record.id).await {
        Ok(token) => Json(TokenResponse { token }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn change_password(
    State(database): State<Database>,
    Json(body): Json<ChangePasswordBody>,
) -> Response {
    let token = legacy_json_string(body.token);
    let Some(old_password) = required_json_string(body.old_password) else {
        return api_error(StatusCode::BAD_REQUEST, "MissingPassword");
    };
    let Some(new_password) = required_json_string(body.new_password) else {
        return api_error(StatusCode::BAD_REQUEST, "MissingPassword");
    };
    if new_password.len() < 8 {
        return api_error(StatusCode::BAD_REQUEST, "PasswordTooShort");
    }
    if new_password.len() > 72 {
        return api_error(StatusCode::BAD_REQUEST, "PasswordTooLong");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };
    let current_hash =
        match sqlx::query_scalar::<_, String>("SELECT password_hash FROM app.users WHERE id = $1")
            .bind(&user.id)
            .fetch_one(pool)
            .await
        {
            Ok(hash) => hash,
            Err(error) => return query_failed(error),
        };
    if current_hash.is_empty() || !verify_password(old_password, current_hash).await {
        return api_error(StatusCode::UNAUTHORIZED, "InvalidCredentials");
    }
    let password_hash = match hash_password(new_password).await {
        Ok(hash) => hash,
        Err(response) => return response,
    };
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    if let Err(error) =
        sqlx::query("UPDATE app.users SET password_hash = $1, updated_at = now() WHERE id = $2")
            .bind(password_hash)
            .bind(&user.id)
            .execute(&mut *transaction)
            .await
    {
        return query_failed(error);
    }
    if let Err(error) = sqlx::query(
        "UPDATE app.sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(&user.id)
    .execute(&mut *transaction)
    .await
    {
        return query_failed(error);
    }
    let new_token = match create_session_executor(&mut transaction, &user.id).await {
        Ok(token) => token,
        Err(error) => return query_failed(error),
    };
    match transaction.commit().await {
        Ok(()) => Json(TokenResponse { token: new_token }).into_response(),
        Err(error) => query_failed(error),
    }
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

async fn create_session(pool: &sqlx::PgPool, user_id: &str) -> Result<String, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let token = create_session_executor(&mut transaction, user_id).await?;
    transaction.commit().await?;
    Ok(token)
}

async fn create_session_executor(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
) -> Result<String, sqlx::Error> {
    let bytes: [u8; 32] = rand::random();
    let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let token_hash = crate::auth::hash_token(&token);
    sqlx::query(
        "INSERT INTO app.sessions (token_hash, user_id, issued_at, expires_at) \
         VALUES ($1, $2, now(), now() + interval '90 days')",
    )
    .bind(token_hash)
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    Ok(token)
}

async fn verify_captcha(token: &str) -> Result<(), Response> {
    let enabled = std::env::var("CF_CAPTCHA_ENABLED")
        .map(|value| value != "false")
        .unwrap_or(true);
    if !enabled {
        tracing::warn!("password login ran with captcha disabled");
        return Ok(());
    }
    if token.is_empty() || token == "undefined" {
        return Err(api_error(StatusCode::BAD_REQUEST, "MissingCaptchaToken"));
    }
    if token.len() > 2048 {
        return Err(api_error(StatusCode::BAD_REQUEST, "InvalidCaptcha"));
    }
    let secret = match std::env::var("CF_CAPTCHA_SECRET") {
        Ok(secret) if !secret.is_empty() => secret,
        _ => {
            tracing::error!("CF_CAPTCHA_SECRET is not configured");
            return Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "CaptchaUnavailable",
            ));
        }
    };
    let client = reqwest::Client::new();
    let response = client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&[("secret", secret.as_str()), ("response", token)])
        .send()
        .await
        .map_err(|error| {
            tracing::error!(%error, "captcha verification request failed");
            api_error(StatusCode::SERVICE_UNAVAILABLE, "CaptchaUnavailable")
        })?;
    if !response.status().is_success() {
        tracing::error!(status = %response.status(), "captcha verification service failed");
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "CaptchaUnavailable",
        ));
    }
    let payload: Value = response.json().await.map_err(|error| {
        tracing::error!(%error, "captcha verification response was invalid");
        api_error(StatusCode::SERVICE_UNAVAILABLE, "CaptchaUnavailable")
    })?;
    if payload.get("success").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(api_error(StatusCode::BAD_REQUEST, "InvalidCaptcha"))
    }
}

async fn verify_password(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
        .await
        .unwrap_or_else(|error| {
            tracing::error!(%error, "password verification task failed");
            false
        })
}

async fn hash_password(password: String) -> Result<String, Response> {
    tokio::task::spawn_blocking(move || bcrypt::hash(password, bcrypt::DEFAULT_COST))
        .await
        .map_err(|error| {
            tracing::error!(%error, "password hashing task failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        })?
        .map_err(|error| {
            tracing::error!(%error, "password hashing failed");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        })
}

fn required_json_string(value: Option<Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) if !value.is_empty() => Some(value),
        Some(Value::String(_)) => None,
        Some(value) if !value.is_null() => {
            let value = value.to_string();
            (!value.is_empty() && value != "undefined" && value != "null").then_some(value)
        }
        _ => None,
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

    #[test]
    fn required_credentials_reject_missing_and_null_values() {
        assert_eq!(required_json_string(None), None);
        assert_eq!(required_json_string(Some(json!(null))), None);
        assert_eq!(required_json_string(Some(json!(""))), None);
        assert_eq!(
            required_json_string(Some(json!("builder"))),
            Some("builder".into())
        );
    }

    #[test]
    fn migrated_bcrypt_hashes_verify() {
        let hash = bcrypt::hash("kinetic-passphrase", bcrypt::DEFAULT_COST).expect("hashes");
        assert!(bcrypt::verify("kinetic-passphrase", &hash).expect("verifies"));
    }

    #[test]
    fn token_response_preserves_legacy_shape() {
        assert_eq!(
            serde_json::to_value(TokenResponse {
                token: "abc123".into()
            })
            .expect("serializes"),
            json!({ "token": "abc123" })
        );
    }
}
