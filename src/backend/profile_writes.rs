use crate::auth::{AuthenticatedUser, authenticate_token};
use crate::db::Database;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ProfileWriteBody {
    token: Option<Value>,
    target: Option<Value>,
    bio: Option<Value>,
    customization: Option<Value>,
    toggle: Option<Value>,
    project: Option<Value>,
    title: Option<Value>,
    private_profile: Option<Value>,
    private_to_following: Option<Value>,
    new_username: Option<Value>,
    email: Option<Value>,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(sqlx::FromRow)]
struct RankEligibility {
    rank: i32,
    eligible: bool,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/users/setBio", post(set_bio))
        .route(
            "/api/v1/users/customization/setCustomization",
            post(set_customization),
        )
        .route(
            "/api/v1/users/customization/setCustomizationDisabled",
            post(set_customization_disabled),
        )
        .route(
            "/api/v1/users/setmyfeaturedproject",
            post(set_featured_project),
        )
        .route("/api/v1/users/privateProfile", post(set_profile_privacy))
        .route("/api/v1/users/requestrankup", post(request_rank_up))
        .route("/api/v1/users/changeUsername", post(change_username))
        .route("/api/v1/users/setEmail", post(set_email))
}

async fn set_bio(State(database): State<Database>, Json(body): Json<ProfileWriteBody>) -> Response {
    let token = legacy_json_string(body.token);
    let bio = legacy_json_string(body.bio);
    if bio.len() > 2048 {
        return api_error(StatusCode::BAD_REQUEST, "BioLengthMustBeLessThan2048Chars");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, &token, StatusCode::BAD_REQUEST).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match contains_illegal_wording(pool, &bio).await {
        Ok(true) => return api_error(StatusCode::BAD_REQUEST, "IllegalWordsUsed"),
        Err(error) => return query_failed(error),
        Ok(false) => {}
    }

    match sqlx::query("UPDATE app.users SET bio = $1 WHERE id = $2")
        .bind(bio)
        .bind(user.id)
        .execute(pool)
        .await
    {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn set_customization(
    State(database): State<Database>,
    Json(body): Json<ProfileWriteBody>,
) -> Response {
    let token = legacy_json_string(body.token);
    let customization = legacy_json_string(body.customization);
    let target = body
        .target
        .map(|value| legacy_json_string(Some(value)).to_lowercase());
    let settings = match serde_json::from_str::<Value>(&customization) {
        Ok(Value::Object(settings)) => Value::Object(settings),
        _ => return api_error(StatusCode::BAD_REQUEST, "Invalid customization JSON"),
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, &token, StatusCode::BAD_REQUEST).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let target_id = if let Some(target) = target {
        if !user.admin && !user.moderator {
            return api_error(StatusCode::UNAUTHORIZED, "Invalid credentials");
        }
        match user_id(pool, &target).await {
            Ok(Some(id)) => id,
            Ok(None) => return api_error(StatusCode::NOT_FOUND, "User does not exist"),
            Err(error) => return query_failed(error),
        }
    } else {
        match has_badge(pool, &user.id, "donator").await {
            Ok(false) => return api_error(StatusCode::FORBIDDEN, "MissingPermission"),
            Err(error) => return query_failed(error),
            Ok(true) => {}
        }
        match customization_disabled(pool, &user.id).await {
            Ok(true) => {
                return api_error(StatusCode::FORBIDDEN, "FeatureDisabledForThisAccount");
            }
            Err(error) => return query_failed(error),
            Ok(false) => user.id,
        }
    };

    match sqlx::query(
        "INSERT INTO app.account_customizations (user_id, settings, updated_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (user_id) DO UPDATE \
         SET settings = EXCLUDED.settings, updated_at = EXCLUDED.updated_at",
    )
    .bind(target_id)
    .bind(settings)
    .execute(pool)
    .await
    {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn set_customization_disabled(
    State(database): State<Database>,
    Json(body): Json<ProfileWriteBody>,
) -> Response {
    let token = legacy_json_string(body.token);
    let target = legacy_json_string(body.target).to_lowercase();
    let is_enabled = legacy_json_bool(body.toggle);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, &token, StatusCode::UNAUTHORIZED).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if !user.admin && !user.moderator {
        return api_error(StatusCode::UNAUTHORIZED, "Invalid credentials");
    }
    let target_id = match user_id(pool, &target).await {
        Ok(Some(id)) => id,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "User does not exist"),
        Err(error) => return query_failed(error),
    };

    match sqlx::query(
        "INSERT INTO app.account_customizations (user_id, disabled, updated_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (user_id) DO UPDATE \
         SET disabled = EXCLUDED.disabled, updated_at = EXCLUDED.updated_at",
    )
    .bind(target_id)
    .bind(!is_enabled)
    .execute(pool)
    .await
    {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn set_profile_privacy(
    State(database): State<Database>,
    Json(body): Json<ProfileWriteBody>,
) -> Response {
    let token = legacy_json_string(body.token);
    let private_profile = legacy_json_bool(body.private_profile);
    let private_to_following = legacy_json_bool(body.private_to_following);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, &token, StatusCode::BAD_REQUEST).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    match sqlx::query(
        "UPDATE app.users \
         SET private_profile = $1, allow_following_view = $2 \
         WHERE id = $3",
    )
    .bind(private_profile)
    .bind(private_to_following)
    .bind(user.id)
    .execute(pool)
    .await
    {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn change_username(
    State(database): State<Database>,
    Json(body): Json<ProfileWriteBody>,
) -> Response {
    let token = legacy_json_string(body.token);
    let display_username = legacy_json_string(body.new_username);
    let username = display_username.to_lowercase();
    if !(3..=20).contains(&username.len()) {
        return api_error(StatusCode::BAD_REQUEST, "InvalidLengthUsername");
    }
    if !username
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return api_error(StatusCode::BAD_REQUEST, "InvalidUsername");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, &token, StatusCode::BAD_REQUEST).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match contains_illegal_wording(pool, &username).await {
        Ok(true) => return api_error(StatusCode::BAD_REQUEST, "IllegalWordsUsed"),
        Err(error) => return query_failed(error),
        Ok(false) => {}
    }
    match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM app.users WHERE username = $1)",
    )
    .bind(&username)
    .fetch_one(pool)
    .await
    {
        Ok(true) => return api_error(StatusCode::NOT_FOUND, "UsernameTaken"),
        Err(error) => return query_failed(error),
        Ok(false) => {}
    }

    match sqlx::query(
        "UPDATE app.users SET username = $1, display_username = $2, updated_at = now() \
         WHERE id = $3",
    )
    .bind(username)
    .bind(display_username)
    .bind(user.id)
    .execute(pool)
    .await
    {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn set_email(
    State(database): State<Database>,
    Json(body): Json<ProfileWriteBody>,
) -> Response {
    let token = legacy_json_string(body.token);
    let email = legacy_json_string(body.email).to_lowercase();
    if !valid_email(&email) {
        return api_error(StatusCode::BAD_REQUEST, "InvalidEmail");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, &token, StatusCode::BAD_REQUEST).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = sqlx::query(
        "INSERT INTO app.user_private_details (user_id, email, updated_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (user_id) DO UPDATE SET email = EXCLUDED.email, updated_at = now()",
    )
    .bind(&user.id)
    .bind(email)
    .execute(&mut *transaction)
    .await
    {
        return if is_unique_violation(&error) {
            api_error(StatusCode::BAD_REQUEST, "EmailAlreadyInUse")
        } else {
            query_failed(error)
        };
    }
    if let Err(error) =
        sqlx::query("UPDATE app.users SET email_verified = false, updated_at = now() WHERE id = $1")
            .bind(user.id)
            .execute(&mut *transaction)
            .await
    {
        return query_failed(error);
    }

    match transaction.commit().await {
        Ok(()) => success(),
        Err(error) => query_failed(error),
    }
}

async fn request_rank_up(
    State(database): State<Database>,
    Json(body): Json<ProfileWriteBody>,
) -> Response {
    let token = legacy_json_string(body.token);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, &token, StatusCode::BAD_REQUEST).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let eligibility = match sqlx::query_as::<_, RankEligibility>(
        "SELECT rank, \
         (((SELECT count(*) FROM app.projects WHERE author_id = u.id) >= 3 \
           AND first_login_at <= now() - interval '5 days') \
          OR cardinality(badges) > 0) AS eligible \
         FROM app.users u WHERE id = $1",
    )
    .bind(&user.id)
    .fetch_one(pool)
    .await
    {
        Ok(eligibility) => eligibility,
        Err(error) => return query_failed(error),
    };
    if eligibility.rank != 0 {
        return api_error(StatusCode::BAD_REQUEST, "AlreadyRankedHighest");
    }
    if !eligibility.eligible {
        return api_error(StatusCode::FORBIDDEN, "Ineligble");
    }

    match sqlx::query("UPDATE app.users SET rank = 1 WHERE id = $1 AND rank = 0")
        .bind(user.id)
        .execute(pool)
        .await
    {
        Ok(result) if result.rows_affected() == 1 => success(),
        Ok(_) => api_error(StatusCode::BAD_REQUEST, "AlreadyRankedHighest"),
        Err(error) => query_failed(error),
    }
}

async fn set_featured_project(
    State(database): State<Database>,
    Json(body): Json<ProfileWriteBody>,
) -> Response {
    let token = legacy_json_string(body.token);
    let project = legacy_json_string(body.project);
    let title = legacy_json_number(body.title);
    if !title.is_finite() || !(0.0..=500.0).contains(&title) {
        return api_error(StatusCode::BAD_REQUEST, "InvalidTitle");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, &token, StatusCode::BAD_REQUEST).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM app.projects WHERE id = $1)")
        .bind(&project)
        .fetch_one(pool)
        .await
    {
        Ok(false) => return api_error(StatusCode::BAD_REQUEST, "InvalidProject"),
        Err(error) => return query_failed(error),
        Ok(true) => {}
    }

    match sqlx::query(
        "UPDATE app.users SET featured_project_id = $1, featured_project_title = $2 WHERE id = $3",
    )
    .bind(project)
    .bind(title.to_string())
    .bind(user.id)
    .execute(pool)
    .await
    {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn authenticate(
    pool: &PgPool,
    token: &str,
    status: StatusCode,
) -> Result<AuthenticatedUser, Response> {
    match authenticate_token(pool, token).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(api_error(status, "Reauthenticate")),
        Err(error) => Err(query_failed(error)),
    }
}

async fn user_id(pool: &PgPool, username: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM app.users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
}

async fn has_badge(pool: &PgPool, user_id: &str, badge: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT $2 = ANY(badges) FROM app.users WHERE id = $1")
        .bind(user_id)
        .bind(badge)
        .fetch_one(pool)
        .await
}

async fn customization_disabled(pool: &PgPool, user_id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE((SELECT disabled FROM app.account_customizations WHERE user_id = $1), false)",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
}

async fn contains_illegal_wording(pool: &PgPool, text: &str) -> Result<bool, sqlx::Error> {
    let words = sqlx::query_scalar::<_, Vec<String>>(
        "SELECT items FROM app.moderation_lists WHERE key IN ('illegalWords', 'illegalWebsites')",
    )
    .fetch_all(pool)
    .await?;
    let text = text.to_lowercase();
    Ok(words
        .into_iter()
        .flatten()
        .filter(|word| !word.is_empty())
        .any(|word| text.contains(&word.to_lowercase())))
}

fn legacy_json_string(value: Option<Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::String(value)) => value,
        Some(Value::Null) => "null".to_owned(),
        Some(value) => value.to_string(),
    }
}

fn legacy_json_bool(value: Option<Value>) -> bool {
    legacy_json_string(value) == "true"
}

fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !local.chars().any(char::is_whitespace)
        && !domain.chars().any(char::is_whitespace)
        && domain
            .rsplit_once('.')
            .is_some_and(|(host, suffix)| !host.is_empty() && suffix.len() >= 2)
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| code == "23505")
}

fn legacy_json_number(value: Option<Value>) -> f64 {
    match value {
        Some(Value::Number(value)) => value.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(value)) => value.parse().unwrap_or(f64::NAN),
        Some(Value::Null) => 0.0,
        Some(Value::Bool(true)) => 1.0,
        Some(Value::Bool(false)) => 0.0,
        _ => f64::NAN,
    }
}

fn success() -> Response {
    Json(SuccessResponse { success: true }).into_response()
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "profile write query failed");
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
    fn legacy_body_coercion_is_preserved() {
        assert_eq!(legacy_json_string(None), "undefined");
        assert!(legacy_json_bool(Some(json!("true"))));
        assert_eq!(legacy_json_number(Some(json!("12"))), 12.0);
    }

    #[test]
    fn featured_title_range_is_inclusive() {
        assert!((0.0..=500.0).contains(&0.0));
        assert!((0.0..=500.0).contains(&500.0));
    }

    #[test]
    fn privacy_flags_match_legacy_string_coercion() {
        assert!(legacy_json_bool(Some(json!(true))));
        assert!(legacy_json_bool(Some(json!("true"))));
        assert!(!legacy_json_bool(Some(json!(1))));
    }

    #[test]
    fn rank_request_preserves_legacy_error_spelling() {
        let response = api_error(StatusCode::FORBIDDEN, "Ineligble");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn email_validation_rejects_incomplete_addresses() {
        assert!(valid_email("builder@example.com"));
        assert!(!valid_email("builder@example"));
        assert!(!valid_email("builder example.com"));
    }

    #[test]
    fn username_character_rule_matches_legacy_route() {
        let valid = |value: &str| {
            value.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        };
        assert!(valid("kinetic_builder-9"));
        assert!(!valid("kinetic builder"));
    }
}
