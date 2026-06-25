use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectQuery {
    project_id: Option<String>,
}

#[derive(Serialize)]
struct ViewingResponse {
    viewing: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UploadResponse {
    can_upload: bool,
}

#[derive(Serialize)]
struct CountResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    loves: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    votes: Option<i64>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/projects/canviewprojects", get(can_view_projects))
        .route(
            "/api/v1/projects/canuploadprojects",
            get(can_upload_projects),
        )
        .route("/api/v1/projects/getLoves", get(get_loves))
        .route("/api/v1/projects/getVotes", get(get_votes))
}

async fn can_view_projects(State(database): State<Database>) -> Response {
    runtime_flag(&database, "viewingEnabled", |value| {
        Json(ViewingResponse { viewing: value }).into_response()
    })
    .await
}

async fn can_upload_projects(State(database): State<Database>) -> Response {
    runtime_flag(&database, "uploadingEnabled", |value| {
        Json(UploadResponse { can_upload: value }).into_response()
    })
    .await
}

async fn get_loves(
    State(database): State<Database>,
    Query(query): Query<ProjectQuery>,
) -> Response {
    project_count(&database, query.project_id, "loves", |count| {
        Json(CountResponse {
            loves: Some(count),
            votes: None,
        })
        .into_response()
    })
    .await
}

async fn get_votes(
    State(database): State<Database>,
    Query(query): Query<ProjectQuery>,
) -> Response {
    project_count(&database, query.project_id, "votes", |count| {
        Json(CountResponse {
            loves: None,
            votes: Some(count),
        })
        .into_response()
    })
    .await
}

async fn runtime_flag<F>(database: &Database, key: &str, respond: F) -> Response
where
    F: FnOnce(bool) -> Response,
{
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, Value>("SELECT value FROM app.runtime_config WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
    {
        Ok(value) => respond(value.and_then(|value| value.as_bool()).unwrap_or(true)),
        Err(error) => query_failed(error),
    }
}

async fn project_count<F>(
    database: &Database,
    project_id: Option<String>,
    column: &'static str,
    respond: F,
) -> Response
where
    F: FnOnce(i64) -> Response,
{
    let Some(project_id) = project_id.filter(|value| !value.is_empty() && value != "undefined")
    else {
        return api_error(StatusCode::BAD_REQUEST, "InvalidProjectID");
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match fetch_project_count(pool, &project_id, column).await {
        Ok(Some(count)) => respond(count),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "Project not found"),
        Err(error) => query_failed(error),
    }
}

async fn fetch_project_count(
    pool: &PgPool,
    project_id: &str,
    column: &'static str,
) -> Result<Option<i64>, sqlx::Error> {
    let query = match column {
        "loves" => "SELECT loves FROM app.projects WHERE id = $1 AND is_public = true",
        "votes" => "SELECT votes FROM app.projects WHERE id = $1 AND is_public = true",
        _ => unreachable!("project count columns are fixed by the router"),
    };

    sqlx::query_scalar(query)
        .bind(project_id)
        .fetch_optional(pool)
        .await
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "public state query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_response_uses_the_legacy_shape() {
        assert_eq!(
            serde_json::to_value(CountResponse {
                loves: Some(3),
                votes: None,
            })
            .expect("serializes"),
            serde_json::json!({ "loves": 3 })
        );
        assert_eq!(
            serde_json::to_value(UploadResponse { can_upload: true }).expect("serializes"),
            serde_json::json!({ "canUpload": true })
        );
    }
}
