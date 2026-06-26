use crate::backend::profile_writes::{parse_birth_date, supported_country, valid_email};
use crate::backend::session_writes::{create_session_executor, hash_password, verify_captcha};
use crate::db::Database;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;

#[derive(Deserialize, Default)]
struct CreateAccountBody {
    username: Option<Value>,
    password: Option<Value>,
    email: Option<Value>,
    birthday: Option<Value>,
    country: Option<Value>,
    captcha_token: Option<Value>,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new().route("/api/v1/users/createAccount", post(create_account))
}

async fn create_account(
    State(database): State<Database>,
    headers: HeaderMap,
    Json(body): Json<CreateAccountBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    match account_creation_enabled(pool).await {
        Ok(false) => {
            return api_error(StatusCode::FORBIDDEN, "Account creation is not enabled");
        }
        Ok(true) => {}
        Err(error) => return query_failed(error),
    }

    let display_username = legacy_json_string(body.username);
    let username = display_username.to_lowercase();
    let password = legacy_json_string(body.password);
    let email = optional_legacy_string(body.email);
    let birthday_text = optional_legacy_string(body.birthday);
    let country = optional_legacy_string(body.country);
    let captcha_token = legacy_json_string(body.captcha_token);

    if let Err(response) = verify_captcha(&captcha_token).await {
        return response;
    }
    if !(3..=20).contains(&username.chars().count()) {
        return api_error(StatusCode::BAD_REQUEST, "InvalidLengthUsername");
    }
    if !username_character_rule(&username) {
        return api_error(StatusCode::BAD_REQUEST, "InvalidUsername");
    }
    if !(8..=50).contains(&password.chars().count()) {
        return api_error(StatusCode::BAD_REQUEST, "InvalidLengthPassword");
    }
    if !password_requirements(&password) {
        return api_error(StatusCode::BAD_REQUEST, "MissingRequirementsPassword");
    }
    if let Some(email) = email.as_deref()
        && !valid_email(email)
    {
        return api_error(StatusCode::BAD_REQUEST, "InvalidEmail");
    }
    let birth_date = match birthday_text.as_deref() {
        Some(value) => match parse_birth_date(value) {
            Some(date) => Some(date),
            None => return api_error(StatusCode::BAD_REQUEST, "InvalidBirthday"),
        },
        None => None,
    };
    if let Some(country) = country.as_deref()
        && !supported_country(country)
    {
        return api_error(StatusCode::BAD_REQUEST, "UnsupportedCountry");
    }

    match username_or_email_conflict(pool, &username, email.as_deref()).await {
        Ok(Some(message)) => return api_error(StatusCode::BAD_REQUEST, message),
        Ok(None) => {}
        Err(error) => return query_failed(error),
    }

    let password_hash = match hash_password(password).await {
        Ok(hash) => hash,
        Err(response) => return response,
    };
    let user_id = ulid::Ulid::new().to_string();
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = sqlx::query(
        "INSERT INTO app.users (
            id, username, display_username, password_hash, first_login_at, last_login_at,
            email_verified, birthday_entered, country_entered, last_privacy_policy_read_at,
            last_terms_read_at, last_guidelines_read_at
         ) VALUES ($1, $2, $3, $4, now(), now(), false, $5, $6, now(), now(), now())",
    )
    .bind(&user_id)
    .bind(&username)
    .bind(&display_username)
    .bind(password_hash)
    .bind(birth_date.is_some())
    .bind(country.is_some())
    .execute(&mut *transaction)
    .await
    {
        return account_insert_failed(error);
    }
    if let Err(error) = sqlx::query(
        "INSERT INTO app.user_private_details (user_id, email, birth_date, country_code)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&user_id)
    .bind(email)
    .bind(birth_date)
    .bind(country)
    .execute(&mut *transaction)
    .await
    {
        return account_insert_failed(error);
    }
    let token = match create_session_executor(&mut transaction, &user_id).await {
        Ok(token) => token,
        Err(error) => return query_failed(error),
    };
    if let Some(ip) = client_ip(&headers)
        && let Err(error) = sqlx::query(
            "INSERT INTO app.logged_ips (user_id, ip, first_seen_at, last_seen_at)
             VALUES ($1, $2::inet, now(), now())
             ON CONFLICT (user_id, ip) DO UPDATE SET last_seen_at = now()",
        )
        .bind(&user_id)
        .bind(ip.to_string())
        .execute(&mut *transaction)
        .await
    {
        return query_failed(error);
    }
    match transaction.commit().await {
        Ok(()) => Json(TokenResponse { token }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn account_creation_enabled(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    let value = sqlx::query_scalar::<_, Value>(
        "SELECT value FROM app.runtime_config WHERE key = 'accountCreationEnabled'",
    )
    .fetch_optional(pool)
    .await?;
    Ok(value.and_then(|value| value.as_bool()).unwrap_or(true))
}

async fn username_or_email_conflict(
    pool: &sqlx::PgPool,
    username: &str,
    email: Option<&str>,
) -> Result<Option<&'static str>, sqlx::Error> {
    if sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM app.users WHERE username = $1)")
        .bind(username)
        .fetch_one(pool)
        .await?
    {
        return Ok(Some("AccountExists"));
    }
    if let Some(email) = email
        && sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM app.user_private_details WHERE email = $1)",
        )
        .bind(email)
        .fetch_one(pool)
        .await?
    {
        return Ok(Some("EmailInUse"));
    }
    Ok(None)
}

fn account_insert_failed(error: sqlx::Error) -> Response {
    if let Some(constraint) = error
        .as_database_error()
        .and_then(|error| error.constraint())
    {
        if constraint == "users_username_unique" {
            return api_error(StatusCode::BAD_REQUEST, "AccountExists");
        }
        if constraint == "user_private_email_unique" {
            return api_error(StatusCode::BAD_REQUEST, "EmailInUse");
        }
    }
    query_failed(error)
}

fn optional_legacy_string(value: Option<Value>) -> Option<String> {
    let value = legacy_json_string(value);
    (!value.is_empty() && value != "undefined" && value != "null").then_some(value)
}

fn legacy_json_string(value: Option<Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::String(value)) => value,
        Some(Value::Null) => "null".to_owned(),
        Some(value) => value.to_string(),
    }
}

fn username_character_rule(username: &str) -> bool {
    username
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
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

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "account creation query failed");
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
    fn username_rules_match_the_legacy_contract() {
        assert!(username_character_rule("kinetic_builder-9"));
        assert!(!username_character_rule("kinetic builder"));
        assert!(!username_character_rule("kinetic.builder"));
        assert!(!username_character_rule("kineticé"));
    }

    #[test]
    fn password_rules_require_each_legacy_character_class() {
        assert!(password_requirements("Playground9!"));
        assert!(!password_requirements("playground9!"));
        assert!(!password_requirements("Playground!"));
        assert!(!password_requirements("Playground9"));
    }

    #[test]
    fn optional_fields_preserve_legacy_string_coercion() {
        assert_eq!(optional_legacy_string(None), None);
        assert_eq!(optional_legacy_string(Some(json!(null))), None);
        assert_eq!(optional_legacy_string(Some(json!(123))), Some("123".into()));
    }

    #[test]
    fn token_response_preserves_the_legacy_shape() {
        assert_eq!(
            serde_json::to_value(TokenResponse {
                token: "abc123".into()
            })
            .expect("serializes"),
            json!({ "token": "abc123" })
        );
    }
}
