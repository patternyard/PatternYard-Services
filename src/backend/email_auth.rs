use crate::auth::{authenticate_token, hash_token};
use crate::backend::profile_writes::valid_email;
use crate::backend::session_writes::{create_session_executor, hash_password, verify_captcha};
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use std::net::IpAddr;

const RESET_PURPOSE: &str = "password_reset";
const VERIFY_PURPOSE: &str = "email_verification";
const EMAIL_COOLDOWN_HOURS: i64 = 2;
const CHALLENGE_LIFETIME_MINUTES: i64 = 30;
const HOME_URL: &str = "https://patternyard.dev";
const API_URL: &str = "https://api.patternyard.dev";

#[derive(Deserialize, Default)]
struct SendResetBody {
    email: Option<Value>,
    captcha_token: Option<Value>,
}

#[derive(Deserialize, Default)]
struct SendVerificationBody {
    token: Option<Value>,
}

#[derive(Deserialize, Default)]
struct ResetPasswordBody {
    email: Option<Value>,
    state: Option<Value>,
    password: Option<Value>,
}

#[derive(Deserialize, Default)]
struct VerifyEmailQuery {
    email: Option<String>,
    state: Option<String>,
}

#[derive(sqlx::FromRow)]
struct EmailUser {
    id: String,
    username: String,
    email: String,
    email_verified: bool,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

#[derive(Debug)]
struct MailjetConfig {
    public_key: String,
    private_key: String,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route(
            "/api/v1/users/resetpassword/sendEmail",
            post(send_reset_email),
        )
        .route(
            "/api/v1/users/resetpassword/sendVerifyEmail",
            post(send_verification_email),
        )
        .route("/api/v1/resetpassword/verifyemail", get(verify_email))
        .route("/api/v1/users/resetpassword/reset", post(reset_password))
}

async fn send_reset_email(
    State(database): State<Database>,
    headers: HeaderMap,
    Json(body): Json<SendResetBody>,
) -> Response {
    let email = legacy_json_string(body.email);
    let captcha_token = legacy_json_string(body.captcha_token);
    if email == "undefined" || captcha_token == "undefined" {
        return api_error(StatusCode::BAD_REQUEST, "MissingFields");
    }
    if let Err(response) = verify_captcha(&captcha_token).await {
        return response;
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    let user = match find_email_user(pool, &email).await {
        Ok(user) => user,
        Err(error) => return query_failed(error),
    };
    let Some(user) = user else {
        return success_response();
    };
    if !valid_email(&user.email) {
        return success_response();
    }

    let requester_hash = client_ip(&headers).map(|ip| hash_private_value(&ip.to_string()));
    match email_on_cooldown(pool, &user.id, requester_hash.as_deref()).await {
        Ok(true) => return success_response(),
        Ok(false) => {}
        Err(error) => return query_failed(error),
    }

    let state = random_token();
    let reset_url = patternyard_url(
        HOME_URL,
        "/resetpassword",
        &[("state", &state), ("email", &user.email)],
    );
    let text = format!(
        "PatternYard Password Reset\n\nHello {}!\n\nSomeone asked to reset the password for this PatternYard account.\n\nReset Password:\n{}\n\nIf you did not ask to reset your password, ignore this message. Do not forward, share, or reply to this email.",
        user.username, reset_url
    );
    let html = format!(
        "<html><body><h1>PatternYard Password Reset</h1><p>Hello {}!</p><p>Someone asked to reset the password for this PatternYard account.</p><p><a href=\"{}\">Reset Password</a></p><p>If you did not ask to reset your password, ignore this message. Do not forward, share, or reply to this email.</p></body></html>",
        escape_html(&user.username),
        escape_html(&reset_url)
    );

    match create_challenge_and_send(
        pool,
        &user,
        requester_hash.as_deref(),
        RESET_PURPOSE,
        &state,
        "Reset Your Password",
        &text,
        &html,
    )
    .await
    {
        Ok(true) => success_response(),
        Ok(false) => {
            // Password-reset requests are deliberately indistinguishable so this route
            // cannot be used to discover whether an account or delivery provider exists.
            success_response()
        }
        Err(error) => query_failed(error),
    }
}

async fn send_verification_email(
    State(database): State<Database>,
    headers: HeaderMap,
    Json(body): Json<SendVerificationBody>,
) -> Response {
    let token = legacy_json_string(body.token);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let authenticated = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };
    let user = match find_user_email_by_id(pool, &authenticated.id).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "EmailInvalid"),
        Err(error) => return query_failed(error),
    };
    if user.email_verified {
        return api_error(StatusCode::BAD_REQUEST, "EmailAlreadyVerified");
    }
    if user.email.is_empty() || !valid_email(&user.email) {
        return api_error(StatusCode::BAD_REQUEST, "EmailInvalid");
    }

    let requester_hash = client_ip(&headers).map(|ip| hash_private_value(&ip.to_string()));
    match email_on_cooldown(pool, &user.id, requester_hash.as_deref()).await {
        Ok(true) => return api_error(StatusCode::BAD_REQUEST, "Cooldown"),
        Ok(false) => {}
        Err(error) => return query_failed(error),
    }

    let state = random_token();
    let verify_url = patternyard_url(
        API_URL,
        "/api/v1/resetpassword/verifyemail",
        &[("email", &user.email), ("state", &state)],
    );
    let text = format!(
        "PatternYard Email Verification\n\nHello {}!\n\nOpen this link to verify the email address for your PatternYard account:\n{}\n\nIf you did not request this, ignore the message. Do not forward, share, or reply to this email.",
        user.username, verify_url
    );
    let html = format!(
        "<html><body><h1>PatternYard Email Verification</h1><p>Hello {}!</p><p>Open this link to verify the email address for your PatternYard account.</p><p><a href=\"{}\">Verify this email</a></p><p>If you did not request this, ignore the message. Do not forward, share, or reply to this email.</p></body></html>",
        escape_html(&user.username),
        escape_html(&verify_url)
    );

    match create_challenge_and_send(
        pool,
        &user,
        requester_hash.as_deref(),
        VERIFY_PURPOSE,
        &state,
        "Verify your email",
        &text,
        &html,
    )
    .await
    {
        Ok(true) => success_response(),
        Ok(false) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "EmailFailed"),
        Err(error) => query_failed(error),
    }
}

async fn verify_email(
    State(database): State<Database>,
    Query(query): Query<VerifyEmailQuery>,
) -> Response {
    let email = query.email.unwrap_or_else(|| "undefined".to_owned());
    let state = query.state.unwrap_or_else(|| "undefined".to_owned());
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    let user_id = match consume_challenge(&mut transaction, &state, &email, VERIFY_PURPOSE).await {
        Ok(Some(user_id)) => user_id,
        Ok(None) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "InvalidState. Your link has most likely expired, please try again.",
            );
        }
        Err(error) => return query_failed(error),
    };
    if let Err(error) =
        sqlx::query("UPDATE app.users SET email_verified = true, updated_at = now() WHERE id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
    {
        return query_failed(error);
    }
    if let Err(error) = transaction.commit().await {
        return query_failed(error);
    }

    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(HOME_URL));
    response
}

async fn reset_password(
    State(database): State<Database>,
    Json(body): Json<ResetPasswordBody>,
) -> Response {
    let email = legacy_json_string(body.email);
    let state = legacy_json_string(body.state);
    let password = legacy_json_string(body.password);
    if !(8..=50).contains(&password.chars().count()) {
        return api_error(StatusCode::BAD_REQUEST, "InvalidLengthPassword");
    }
    if !password_requirements(&password) {
        return api_error(StatusCode::BAD_REQUEST, "MissingRequirementsPassword");
    }
    let password_hash = match hash_password(password).await {
        Ok(hash) => hash,
        Err(response) => return response,
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    let user_id = match consume_challenge(&mut transaction, &state, &email, RESET_PURPOSE).await {
        Ok(Some(user_id)) => user_id,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "InvalidState"),
        Err(error) => return query_failed(error),
    };
    if let Err(error) =
        sqlx::query("UPDATE app.users SET password_hash = $1, updated_at = now() WHERE id = $2")
            .bind(password_hash)
            .bind(&user_id)
            .execute(&mut *transaction)
            .await
    {
        return query_failed(error);
    }
    if let Err(error) = sqlx::query(
        "UPDATE app.sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(&user_id)
    .execute(&mut *transaction)
    .await
    {
        return query_failed(error);
    }
    let token = match create_session_executor(&mut transaction, &user_id).await {
        Ok(token) => token,
        Err(error) => return query_failed(error),
    };
    match transaction.commit().await {
        Ok(()) => Json(TokenResponse { token }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn find_email_user(pool: &PgPool, email: &str) -> Result<Option<EmailUser>, sqlx::Error> {
    sqlx::query_as::<_, EmailUser>(
        "SELECT u.id, u.username::text AS username, p.email::text AS email, u.email_verified
         FROM app.users u
         JOIN app.user_private_details p ON p.user_id = u.id
         WHERE p.email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
}

async fn find_user_email_by_id(
    pool: &PgPool,
    user_id: &str,
) -> Result<Option<EmailUser>, sqlx::Error> {
    sqlx::query_as::<_, EmailUser>(
        "SELECT u.id, u.username::text AS username, p.email::text AS email, u.email_verified
         FROM app.users u
         JOIN app.user_private_details p ON p.user_id = u.id
         WHERE u.id = $1 AND p.email IS NOT NULL",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

async fn email_on_cooldown(
    pool: &PgPool,
    user_id: &str,
    requester_hash: Option<&[u8]>,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM app.email_delivery_log
            WHERE created_at > now() - make_interval(hours => $3)
              AND (user_id = $1 OR ($2::bytea IS NOT NULL AND requester_hash = $2))
        )",
    )
    .bind(user_id)
    .bind(requester_hash)
    .bind(EMAIL_COOLDOWN_HOURS as i32)
    .fetch_one(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
async fn create_challenge_and_send(
    pool: &PgPool,
    user: &EmailUser,
    requester_hash: Option<&[u8]>,
    purpose: &str,
    token: &str,
    subject: &str,
    text: &str,
    html: &str,
) -> Result<bool, sqlx::Error> {
    let config = match mailjet_config() {
        Some(config) => config,
        None => {
            tracing::error!("Mailjet credentials are not configured");
            return Ok(false);
        }
    };
    let expires_at = Utc::now() + Duration::minutes(CHALLENGE_LIFETIME_MINUTES);
    let token_hash = hash_token(token);
    let mut transaction = pool.begin().await?;
    sqlx::query("DELETE FROM app.password_reset_challenges WHERE user_id = $1 AND purpose = $2")
        .bind(&user.id)
        .bind(purpose)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO app.password_reset_challenges
            (token_hash, user_id, purpose, created_at, expires_at)
         VALUES ($1, $2, $3, now(), $4)",
    )
    .bind(token_hash)
    .bind(&user.id)
    .bind(purpose)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;

    let provider_message_id = match send_mailjet(&config, user, subject, text, html).await {
        Ok(message_id) => message_id,
        Err(error) => {
            tracing::error!(%error, purpose, "email delivery failed");
            return Ok(false);
        }
    };
    sqlx::query(
        "INSERT INTO app.email_delivery_log
            (user_id, purpose, recipient_hash, requester_hash, created_at, provider_message_id)
         VALUES ($1, $2, $3, $4, now(), $5)",
    )
    .bind(&user.id)
    .bind(purpose)
    .bind(hash_private_value(&user.email))
    .bind(requester_hash)
    .bind(provider_message_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(true)
}

async fn consume_challenge(
    transaction: &mut Transaction<'_, Postgres>,
    token: &str,
    email: &str,
    purpose: &str,
) -> Result<Option<String>, sqlx::Error> {
    let token_hash = hash_token(token);
    sqlx::query_scalar(
        "UPDATE app.password_reset_challenges c
         SET consumed_at = now()
         FROM app.user_private_details p
         WHERE c.token_hash = $1
           AND c.purpose = $2
           AND c.user_id = p.user_id
           AND p.email = $3
           AND c.consumed_at IS NULL
           AND c.expires_at > now()
         RETURNING c.user_id",
    )
    .bind(token_hash)
    .bind(purpose)
    .bind(email)
    .fetch_optional(&mut **transaction)
    .await
}

async fn send_mailjet(
    config: &MailjetConfig,
    user: &EmailUser,
    subject: &str,
    text: &str,
    html: &str,
) -> Result<Option<String>, reqwest::Error> {
    let response = reqwest::Client::new()
        .post("https://api.mailjet.com/v3.1/send")
        .basic_auth(&config.public_key, Some(&config.private_key))
        .json(&json!({
            "Messages": [{
                "From": {"Email": "no-reply@patternyard.dev", "Name": "PatternYard"},
                "To": [{"Email": user.email, "Name": user.username}],
                "Subject": subject,
                "TextPart": text,
                "HTMLPart": html
            }]
        }))
        .send()
        .await?
        .error_for_status()?;
    let payload: Value = response.json().await?;
    Ok(payload
        .pointer("/Messages/0/To/0/MessageID")
        .and_then(Value::as_i64)
        .map(|id| id.to_string()))
}

fn mailjet_config() -> Option<MailjetConfig> {
    let public_key = std::env::var("MJ_API_KEY_PUBLIC").ok()?;
    let private_key = std::env::var("MJ_API_KEY_PRIVATE").ok()?;
    if public_key.is_empty() || private_key.is_empty() {
        return None;
    }
    Some(MailjetConfig {
        public_key,
        private_key,
    })
}

fn patternyard_url(base: &str, path: &str, pairs: &[(&str, &str)]) -> String {
    let mut url = reqwest::Url::parse(base).expect("PatternYard base URLs are static and valid");
    url.set_path(path);
    url.query_pairs_mut().extend_pairs(pairs.iter().copied());
    url.to_string()
}

fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_private_value(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

fn password_requirements(password: &str) -> bool {
    password
        .chars()
        .any(|character| character.is_ascii_lowercase())
        && password
            .chars()
            .any(|character| character.is_ascii_uppercase())
        && password.chars().any(|character| character.is_ascii_digit())
        && password
            .chars()
            .any(|character| !character.is_ascii_alphanumeric())
}

fn legacy_json_string(value: Option<Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::String(value)) => value,
        Some(Value::Null) => "null".to_owned(),
        Some(value) => value.to_string(),
    }
}

fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .and_then(|value| value.parse().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
        })
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn success_response() -> Response {
    Json(SuccessResponse { success: true }).into_response()
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "email authentication query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_have_full_random_hex_length() {
        let token = random_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|character| character.is_ascii_hexdigit()));
    }

    #[test]
    fn links_are_encoded_and_patternyard_only() {
        let link = patternyard_url(
            HOME_URL,
            "/resetpassword",
            &[("state", "a&b"), ("email", "builder+test@example.com")],
        );
        assert!(link.starts_with("https://patternyard.dev/resetpassword?"));
        assert!(link.contains("state=a%26b"));
        assert!(link.contains("email=builder%2Btest%40example.com"));
        assert!(!link.contains("penguinmod.com"));
    }

    #[test]
    fn html_content_is_escaped() {
        assert_eq!(
            escape_html("<builder's \"yard\">"),
            "&lt;builder&#39;s &quot;yard&quot;&gt;"
        );
    }

    #[test]
    fn reset_password_requires_all_character_classes() {
        assert!(password_requirements("Playground9!"));
        assert!(!password_requirements("playground9!"));
        assert!(!password_requirements("Playground!"));
        assert!(!password_requirements("Playground9"));
    }

    #[test]
    fn private_values_are_not_stored_in_plain_text() {
        let value = "private@example.com";
        let hash = hash_private_value(value);
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, value.as_bytes());
    }

    #[test]
    fn email_cooldown_matches_the_documented_window() {
        assert_eq!(EMAIL_COOLDOWN_HOURS, 2);
    }
}
