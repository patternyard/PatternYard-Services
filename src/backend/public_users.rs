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
    let Some(username) = required(query.username, "Missing username") else {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    };
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

async fn get_id(
    State(database): State<Database>,
    Query(query): Query<UsernameQuery>,
) -> Response {
    let Some(username) = required(query.username, "Missing username") else {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    };
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

async fn get_username(
    State(database): State<Database>,
    Query(query): Query<IdQuery>,
) -> Response {
    let Some(id) = required(query.id, "Missing ID") else {
        return api_error(StatusCode::BAD_REQUEST, "Missing ID");
    };
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
    let Some(username) = required(query.username, "Missing username") else {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, Vec<String>>(
        "SELECT badges FROM app.users WHERE username = $1",
    )
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
    let Some(username) = required(query.username, "Missing username") else {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, i32>(
        "SELECT follower_count FROM app.users WHERE username = $1",
    )
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
    let Some(target) = required(body.target, "Missing target") else {
        return api_error(StatusCode::BAD_REQUEST, "Missing target");
    };
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

fn required(value: Option<String>, _error: &'static str) -> Option<String> {
    value
        .map(|value| value.to_lowercase())
        .filter(|value| !value.is_empty() && value != "undefined")
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
    fn normalizes_usernames_but_not_empty_values() {
        assert_eq!(required(Some("NewUser".into()), "ignored"), Some("newuser".into()));
        assert_eq!(required(Some("undefined".into()), "ignored"), None);
        assert_eq!(required(None, "ignored"), None);
    }

    #[test]
    fn missing_follower_count_serializes_as_empty_object() {
        let response = serde_json::to_value(CountResponse { count: None }).expect("serializes");
        assert_eq!(response, serde_json::Value::Object(Default::default()));
    }
}
