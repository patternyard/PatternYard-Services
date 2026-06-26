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
use std::collections::BTreeSet;

#[derive(Deserialize, Default)]
struct TargetBody {
    token: Option<String>,
    target: Option<String>,
}

#[derive(Deserialize)]
struct SetBadgesBody {
    token: Option<String>,
    target: Option<String>,
    badges: Value,
}

#[derive(Deserialize)]
struct SetBadgesMultipleBody {
    token: Option<String>,
    targets: Value,
    badges: Value,
    removing: Option<Value>,
}

#[derive(Deserialize)]
struct SetBioBody {
    token: Option<String>,
    target: Option<String>,
    bio: Option<String>,
}

#[derive(Deserialize)]
struct SetFeaturedBody {
    token: Option<String>,
    target: Option<String>,
    project: Option<String>,
    title: Option<Value>,
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
        .route("/api/v1/users/setBadges", post(set_badges))
        .route("/api/v1/users/setbadgesmultiple", post(set_badges_multiple))
        .route("/api/v1/users/setbioadmin", post(set_bio_admin))
        .route(
            "/api/v1/users/setmyfeaturedprojectadmin",
            post(set_featured_project_admin),
        )
        .route("/api/v1/users/verifyfollowers", post(verify_followers))
}

async fn set_badges(State(database): State<Database>, Json(body): Json<SetBadgesBody>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, body.token).await {
        return response;
    }
    let target = legacy_username(body.target);
    let badges = match string_array(&body.badges) {
        Some(badges) => badges,
        None => return api_error(StatusCode::BAD_REQUEST, "InvalidBadges"),
    };
    match sqlx::query("UPDATE app.users SET badges = $2, updated_at = now() WHERE username = $1")
        .bind(target)
        .bind(badges)
        .execute(pool)
        .await
    {
        Ok(result) if result.rows_affected() == 1 => success(),
        Ok(_) => api_error(StatusCode::NOT_FOUND, "UserNotFound"),
        Err(error) => query_failed(error),
    }
}

async fn set_badges_multiple(
    State(database): State<Database>,
    Json(body): Json<SetBadgesMultipleBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, body.token).await {
        return response;
    }
    let targets = match string_array(&body.targets) {
        Some(targets) => targets,
        None => return api_error(StatusCode::BAD_REQUEST, "InvalidTargets"),
    };
    let badges = match string_array(&body.badges) {
        Some(badges) => badges,
        None => return api_error(StatusCode::BAD_REQUEST, "InvalidBadges"),
    };
    let removing = legacy_bool(body.removing.as_ref());
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    for target in targets {
        let target = target.to_lowercase();
        let current = match sqlx::query_scalar::<_, Vec<String>>(
            "SELECT badges FROM app.users WHERE username = $1",
        )
        .bind(&target)
        .fetch_optional(&mut *transaction)
        .await
        {
            Ok(Some(current)) => current,
            Ok(None) => {
                return api_error_owned(StatusCode::NOT_FOUND, format!("UserNotFound {target}"));
            }
            Err(error) => return query_failed(error),
        };
        let mut merged = current.into_iter().collect::<BTreeSet<_>>();
        for badge in &badges {
            if removing {
                merged.remove(badge);
            } else {
                merged.insert(badge.clone());
            }
        }
        if let Err(error) =
            sqlx::query("UPDATE app.users SET badges = $2, updated_at = now() WHERE username = $1")
                .bind(target)
                .bind(merged.into_iter().collect::<Vec<_>>())
                .execute(&mut *transaction)
                .await
        {
            return query_failed(error);
        }
    }
    match transaction.commit().await {
        Ok(()) => success(),
        Err(error) => query_failed(error),
    }
}

async fn set_bio_admin(State(database): State<Database>, Json(body): Json<SetBioBody>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_moderator(pool, body.token).await {
        return response;
    }
    let target = legacy_username(body.target);
    let bio = body.bio.unwrap_or_else(|| "undefined".to_owned());
    if bio.chars().count() > 2048 {
        return api_error(StatusCode::BAD_REQUEST, "BioLengthMustBeLessThan2048Chars");
    }
    match sqlx::query("UPDATE app.users SET bio = $2, updated_at = now() WHERE username = $1")
        .bind(target)
        .bind(bio)
        .execute(pool)
        .await
    {
        Ok(result) if result.rows_affected() == 1 => success(),
        Ok(_) => api_error(StatusCode::NOT_FOUND, "UserNotFound"),
        Err(error) => query_failed(error),
    }
}

async fn set_featured_project_admin(
    State(database): State<Database>,
    Json(body): Json<SetFeaturedBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_moderator(pool, body.token).await {
        return response;
    }
    let target = legacy_username(body.target);
    let project = legacy_string(body.project);
    let title = body
        .title
        .map(legacy_value_string)
        .unwrap_or_else(|| "undefined".to_owned());
    if project.is_empty() || title.chars().count() > 500 {
        return api_error(StatusCode::BAD_REQUEST, "InvalidInput");
    }
    let exists = match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM app.projects WHERE id = $1)",
    )
    .bind(&project)
    .fetch_one(pool)
    .await
    {
        Ok(exists) => exists,
        Err(error) => return query_failed(error),
    };
    if !exists {
        return api_error(StatusCode::BAD_REQUEST, "InvalidProject");
    }
    match sqlx::query(
        "UPDATE app.users SET featured_project_id = $2, featured_project_title = $3, updated_at = now() WHERE username = $1",
    )
    .bind(target)
    .bind(project)
    .bind(title)
    .execute(pool)
    .await
    {
        Ok(result) if result.rows_affected() == 1 => success(),
        Ok(_) => api_error(StatusCode::NOT_FOUND, "UserNotFound"),
        Err(error) => query_failed(error),
    }
}

async fn verify_followers(
    State(database): State<Database>,
    Json(body): Json<TargetBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = require_admin(pool, body.token).await {
        return response;
    }
    let target = legacy_username(body.target);
    let result = sqlx::query(
        "UPDATE app.users users SET \
         follower_count = (SELECT count(*)::integer FROM app.follows WHERE target_id = users.id AND active), \
         following_count = (SELECT count(*)::integer FROM app.follows WHERE follower_id = users.id AND active), \
         updated_at = now() WHERE users.username = $1",
    )
    .bind(target)
    .execute(pool)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => success(),
        Ok(_) => api_error(StatusCode::NOT_FOUND, "UserNotFound"),
        Err(error) => query_failed(error),
    }
}

async fn authenticate(pool: &PgPool, token: Option<String>) -> Result<AuthenticatedUser, Response> {
    let token = legacy_string(token);
    match authenticate_token(pool, &token).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(api_error(StatusCode::BAD_REQUEST, "Reauthenticate")),
        Err(error) => Err(query_failed(error)),
    }
}

async fn require_admin(pool: &PgPool, token: Option<String>) -> Result<(), Response> {
    let user = authenticate(pool, token).await?;
    if user.admin {
        Ok(())
    } else {
        Err(api_error(StatusCode::FORBIDDEN, "Unauthorized"))
    }
}

async fn require_moderator(pool: &PgPool, token: Option<String>) -> Result<(), Response> {
    let user = authenticate(pool, token).await?;
    if user.admin || user.moderator {
        Ok(())
    } else {
        Err(api_error(StatusCode::FORBIDDEN, "Unauthorized"))
    }
}

fn string_array(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(ToOwned::to_owned))
        .collect()
}
fn legacy_bool(value: Option<&Value>) -> bool {
    value.is_some_and(|value| match value {
        Value::Bool(value) => *value,
        Value::String(value) => value == "true",
        _ => false,
    })
}
fn legacy_value_string(value: Value) -> String {
    match value {
        Value::String(value) => value,
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => "null".to_owned(),
        other => other.to_string(),
    }
}
fn legacy_string(value: Option<String>) -> String {
    value.unwrap_or_else(|| "undefined".to_owned())
}
fn legacy_username(value: Option<String>) -> String {
    legacy_string(value).to_lowercase()
}
fn success() -> Response {
    Json(SuccessResponse { success: true }).into_response()
}
fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}
fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "user moderation write failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}
fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}
fn api_error_owned(status: StatusCode, message: String) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badge_arrays_require_strings() {
        assert_eq!(
            string_array(&serde_json::json!(["helper", "artist"]))
                .unwrap()
                .len(),
            2
        );
        assert!(string_array(&serde_json::json!([1])).is_none());
    }

    #[test]
    fn legacy_boolean_coercion_accepts_strings() {
        assert!(legacy_bool(Some(&serde_json::json!("true"))));
        assert!(!legacy_bool(Some(&serde_json::json!("false"))));
    }
}
