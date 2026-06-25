use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
struct UsernameQuery {
    username: Option<String>,
}

#[derive(Deserialize)]
struct IdQuery {
    #[serde(rename = "ID", alias = "id")]
    id: Option<String>,
}

#[derive(Deserialize)]
struct ProjectCountBody {
    target: Option<String>,
}

#[derive(Serialize)]
struct ExistsResponse {
    exists: bool,
}

#[derive(Serialize)]
struct IdResponse {
    id: String,
}

#[derive(Serialize)]
struct BadgesResponse {
    badges: Vec<String>,
}

#[derive(Serialize)]
struct CountResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<i64>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/users/userexists", get(user_exists))
        .route("/api/v1/users/getid", get(get_id))
        .route("/api/v1/users/getusername", get(get_username))
        .route("/api/v1/users/getBadges", get(get_badges))
        .route(
            "/api/v1/users/meta/getfollowercount",
            get(get_follower_count),
        )
        .route(
            "/api/v1/users/getprojectcountofuser",
            post(get_project_count),
        )
}

async fn user_exists(
    State(database): State<Database>,
    Query(query): Query<UsernameQuery>,
) -> Response {
    let username = legacy_username(query.username);
    if username.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM app.users WHERE username = $1)",
    )
    .bind(username)
    .fetch_one(pool)
    .await
    {
        Ok(exists) => Json(ExistsResponse { exists }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_id(State(database): State<Database>, Query(query): Query<UsernameQuery>) -> Response {
    let username = legacy_username(query.username);
    if username.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, String>("SELECT id FROM app.users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(id)) => Json(IdResponse { id }).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "UserNotFound"),
        Err(error) => query_failed(error),
    }
}

async fn get_username(State(database): State<Database>, Query(query): Query<IdQuery>) -> Response {
    let id = legacy_string(query.id);
    if id.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing ID");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, String>("SELECT username::text FROM app.users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(username)) => Json(json!({ "username": username })).into_response(),
        Ok(None) => Json(json!({ "username": false })).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_badges(
    State(database): State<Database>,
    Query(query): Query<UsernameQuery>,
) -> Response {
    let username = legacy_username(query.username);
    if username.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, Vec<String>>("SELECT badges FROM app.users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(badges)) => Json(BadgesResponse { badges }).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "NotFound"),
        Err(error) => query_failed(error),
    }
}

async fn get_follower_count(
    State(database): State<Database>,
    Query(query): Query<UsernameQuery>,
) -> Response {
    let username = legacy_username(query.username);
    if username.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, i32>("SELECT follower_count FROM app.users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
    {
        Ok(count) => Json(CountResponse {
            count: count.map(i64::from),
        })
        .into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_project_count(
    State(database): State<Database>,
    Json(body): Json<ProjectCountBody>,
) -> Response {
    let target = legacy_username(body.target);
    if target.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing target");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, i64>(
        "SELECT count(p.id) FROM app.users u LEFT JOIN app.projects p ON p.author_id = u.id WHERE u.username = $1 GROUP BY u.id",
    )
    .bind(target)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(count)) => Json(CountResponse { count: Some(count) }).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "User does not exist"),
        Err(error) => query_failed(error),
    }
}

fn legacy_string(value: Option<String>) -> String {
    value.unwrap_or_else(|| "undefined".to_owned())
}

fn legacy_username(value: Option<String>) -> String {
    legacy_string(value).to_lowercase()
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "public user query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_legacy_string_coercion() {
        assert_eq!(legacy_username(Some("NewUser".into())), "newuser");
        assert_eq!(legacy_username(None), "undefined");
        assert_eq!(
            legacy_string(Some("CaseSensitiveID".into())),
            "CaseSensitiveID"
        );
        assert_eq!(legacy_string(None), "undefined");
    }

    #[test]
    fn missing_follower_count_serializes_as_empty_object() {
        let response = serde_json::to_value(CountResponse { count: None }).expect("serializes");
        assert_eq!(response, serde_json::Value::Object(Default::default()));
    }
}
