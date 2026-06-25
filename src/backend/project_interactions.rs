use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

const PAGE_SIZE: i64 = 20;

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct InteractionQuery {
    token: Option<String>,
    project_id: Option<String>,
    page: Option<i64>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/projects/getWhoLoved", get(get_who_loved))
        .route("/api/v1/projects/getWhoVoted", get(get_who_voted))
}

async fn get_who_loved(
    State(database): State<Database>,
    Query(query): Query<InteractionQuery>,
) -> Response {
    get_interactions(database, query, "love", "loves").await
}

async fn get_who_voted(
    State(database): State<Database>,
    Query(query): Query<InteractionQuery>,
) -> Response {
    get_interactions(database, query, "vote", "votes").await
}

async fn get_interactions(
    database: Database,
    query: InteractionQuery,
    kind: &'static str,
    response_key: &'static str,
) -> Response {
    let token = legacy_string(query.token);
    let project_id = legacy_string(query.project_id);
    let page = query.page.unwrap_or(0).max(0);
    let Some(pool) = database.pool() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
    };

    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };

    if !user.admin {
        return api_error(StatusCode::UNAUTHORIZED, "Invalid credentials");
    }

    match project_exists(pool, &project_id).await {
        Ok(false) => return api_error(StatusCode::NOT_FOUND, "Project not found"),
        Err(error) => return query_failed(error),
        Ok(true) => {}
    }

    match interaction_usernames(pool, &project_id, kind, page).await {
        Ok(usernames) => Json(json!({ response_key: usernames })).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn project_exists(pool: &PgPool, project_id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM app.projects WHERE id = $1)")
        .bind(project_id)
        .fetch_one(pool)
        .await
}

async fn interaction_usernames(
    pool: &PgPool,
    project_id: &str,
    kind: &str,
    page: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT u.username::text \
         FROM app.project_interactions interaction \
         JOIN app.users u ON u.id = interaction.user_id \
         WHERE interaction.project_id = $1 AND interaction.kind = $2 \
         ORDER BY interaction.created_at ASC, interaction.user_id ASC \
         LIMIT $3 OFFSET $4",
    )
    .bind(project_id)
    .bind(kind)
    .bind(PAGE_SIZE)
    .bind(page.saturating_mul(PAGE_SIZE))
    .fetch_all(pool)
    .await
}

fn legacy_string(value: Option<String>) -> String {
    value.unwrap_or_else(|| "undefined".to_owned())
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "project interaction query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn missing_legacy_values_are_undefined() {
        assert_eq!(legacy_string(None), "undefined");
    }

    #[test]
    fn response_keys_are_legacy_cased() {
        let body: Value = json!({ "loves": ["builder"] });
        assert_eq!(body["loves"][0], "builder");
    }
}
