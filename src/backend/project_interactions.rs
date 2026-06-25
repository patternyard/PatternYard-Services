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
    #[serde(alias = "projectID")]
    project_id: Option<String>,
    target: Option<String>,
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
        .route("/api/v1/projects/hasLoved", get(has_loved))
        .route("/api/v1/projects/hasVoted", get(has_voted))
        .route("/api/v1/projects/hasLovedAdmin", get(has_loved_admin))
        .route("/api/v1/projects/hasVotedAdmin", get(has_voted_admin))
        .route(
            "/api/v1/projects/getuserstatewrapper",
            get(get_user_state_wrapper),
        )
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

async fn has_loved(
    State(database): State<Database>,
    Query(query): Query<InteractionQuery>,
) -> Response {
    get_interaction_state(database, query, "love", "hasLoved", false).await
}

async fn has_voted(
    State(database): State<Database>,
    Query(query): Query<InteractionQuery>,
) -> Response {
    get_interaction_state(database, query, "vote", "hasVoted", false).await
}

async fn has_loved_admin(
    State(database): State<Database>,
    Query(query): Query<InteractionQuery>,
) -> Response {
    get_interaction_state(database, query, "love", "hasLoved", true).await
}

async fn has_voted_admin(
    State(database): State<Database>,
    Query(query): Query<InteractionQuery>,
) -> Response {
    get_interaction_state(database, query, "vote", "hasVoted", true).await
}

async fn get_user_state_wrapper(
    State(database): State<Database>,
    Query(query): Query<InteractionQuery>,
) -> Response {
    let token = legacy_string(query.token);
    let project_id = legacy_string(query.project_id);
    let Some(pool) = database.pool() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
    };

    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };

    match project_exists(pool, &project_id).await {
        Ok(false) => return api_error(StatusCode::NOT_FOUND, "Project not found"),
        Err(error) => return query_failed(error),
        Ok(true) => {}
    }

    match interaction_states(pool, &project_id, &user.id).await {
        Ok((has_loved, has_voted)) => {
            Json(json!({ "hasLoved": has_loved, "hasVoted": has_voted })).into_response()
        }
        Err(error) => query_failed(error),
    }
}

async fn get_interaction_state(
    database: Database,
    query: InteractionQuery,
    kind: &'static str,
    response_key: &'static str,
    admin_target: bool,
) -> Response {
    let token = legacy_string(query.token);
    let project_id = legacy_string(query.project_id);
    let target = legacy_string(query.target).to_lowercase();
    let Some(pool) = database.pool() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
    };

    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };

    if admin_target && !user.admin {
        return api_error(StatusCode::UNAUTHORIZED, "Invalid credentials");
    }

    match project_exists(pool, &project_id).await {
        Ok(false) => return api_error(StatusCode::NOT_FOUND, "Project not found"),
        Err(error) => return query_failed(error),
        Ok(true) => {}
    }

    let target_id = if admin_target {
        match user_id_by_username(pool, &target).await {
            Ok(target_id) => target_id,
            Err(error) => return query_failed(error),
        }
    } else {
        Some(user.id)
    };

    let has = match target_id {
        Some(target_id) => match has_interaction(pool, &project_id, &target_id, kind).await {
            Ok(has) => has,
            Err(error) => return query_failed(error),
        },
        None => false,
    };

    Json(json!({ response_key: has })).into_response()
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

async fn user_id_by_username(pool: &PgPool, username: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>("SELECT id FROM app.users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
}

async fn has_interaction(
    pool: &PgPool,
    project_id: &str,
    user_id: &str,
    kind: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(\
            SELECT 1 FROM app.project_interactions \
            WHERE project_id = $1 AND user_id = $2 AND kind = $3\
        )",
    )
    .bind(project_id)
    .bind(user_id)
    .bind(kind)
    .fetch_one(pool)
    .await
}

async fn interaction_states(
    pool: &PgPool,
    project_id: &str,
    user_id: &str,
) -> Result<(bool, bool), sqlx::Error> {
    sqlx::query_as::<_, (bool, bool)>(
        "SELECT \
            EXISTS(SELECT 1 FROM app.project_interactions WHERE project_id = $1 AND user_id = $2 AND kind = 'love'), \
            EXISTS(SELECT 1 FROM app.project_interactions WHERE project_id = $1 AND user_id = $2 AND kind = 'vote')",
    )
    .bind(project_id)
    .bind(user_id)
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
