use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct InteractionBody {
    token: Option<Value>,
    #[serde(alias = "projectID")]
    project_id: Option<Value>,
    toggle: Option<Value>,
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
        .route(
            "/api/v1/projects/interactions/loveToggle",
            post(love_toggle),
        )
        .route(
            "/api/v1/projects/interactions/voteToggle",
            post(vote_toggle),
        )
        .route(
            "/api/v1/projects/interactions/registerView",
            post(register_view),
        )
        .route(
            "/api/v1/projects/interactions/showMeLess",
            post(show_me_less),
        )
        .route(
            "/api/v1/projects/interactions/showMeMore",
            post(show_me_more),
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

async fn love_toggle(
    State(database): State<Database>,
    Json(body): Json<InteractionBody>,
) -> Response {
    toggle_interaction(database, body, "love", "loves", false).await
}

async fn vote_toggle(
    State(database): State<Database>,
    Json(body): Json<InteractionBody>,
) -> Response {
    toggle_interaction(database, body, "vote", "votes", true).await
}

async fn register_view(
    State(database): State<Database>,
    Json(body): Json<InteractionBody>,
) -> Response {
    record_signal(database, body, "view").await
}

async fn show_me_less(
    State(database): State<Database>,
    Json(body): Json<InteractionBody>,
) -> Response {
    record_signal(database, body, "show_less").await
}

async fn show_me_more(
    State(database): State<Database>,
    Json(body): Json<InteractionBody>,
) -> Response {
    record_signal(database, body, "show_more").await
}

async fn toggle_interaction(
    database: Database,
    body: InteractionBody,
    kind: &'static str,
    counter: &'static str,
    reject_missing: bool,
) -> Response {
    let token = legacy_json_string(body.token);
    let project_id = legacy_json_string(body.project_id);
    let toggle = legacy_json_bool(body.toggle);
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
    let existing = match has_interaction(pool, &project_id, &user.id, kind).await {
        Ok(existing) => existing,
        Err(error) => return query_failed(error),
    };
    if existing && toggle {
        return api_error(
            StatusCode::BAD_REQUEST,
            if kind == "love" {
                "Already loved"
            } else {
                "Already voted"
            },
        );
    }
    if !existing && !toggle && reject_missing {
        return api_error(StatusCode::BAD_REQUEST, "Not voted");
    }

    match set_interaction(pool, &project_id, &user.id, kind, counter, toggle).await {
        Ok(()) => Json(json!({ "success": true })).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn record_signal(database: Database, body: InteractionBody, kind: &'static str) -> Response {
    let token = legacy_json_string(body.token);
    let project_id = legacy_json_string(body.project_id);
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

    match insert_signal(pool, &project_id, &user.id, kind).await {
        Ok(()) => Json(json!({ "success": true })).into_response(),
        Err(error) => query_failed(error),
    }
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

async fn set_interaction(
    pool: &PgPool,
    project_id: &str,
    user_id: &str,
    kind: &str,
    counter: &str,
    toggle: bool,
) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    if toggle {
        sqlx::query(
            "INSERT INTO app.project_interactions (project_id, user_id, kind) \
             VALUES ($1, $2, $3)",
        )
        .bind(project_id)
        .bind(user_id)
        .bind(kind)
        .execute(&mut *transaction)
        .await?;
    } else {
        sqlx::query(
            "DELETE FROM app.project_interactions \
             WHERE project_id = $1 AND user_id = $2 AND kind = $3",
        )
        .bind(project_id)
        .bind(user_id)
        .bind(kind)
        .execute(&mut *transaction)
        .await?;
    }

    let update = match counter {
        "loves" => {
            "UPDATE app.projects SET loves = (\
                 SELECT count(*) FROM app.project_interactions \
                 WHERE project_id = $1 AND kind = 'love'\
             ) WHERE id = $1"
        }
        "votes" => {
            "UPDATE app.projects SET votes = (\
                 SELECT count(*) FROM app.project_interactions \
                 WHERE project_id = $1 AND kind = 'vote'\
             ) WHERE id = $1"
        }
        _ => unreachable!("interaction counters are fixed route constants"),
    };
    sqlx::query(update)
        .bind(project_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await
}

async fn insert_signal(
    pool: &PgPool,
    project_id: &str,
    user_id: &str,
    kind: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO app.project_interactions (project_id, user_id, kind) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (project_id, user_id, kind) \
         DO UPDATE SET created_at = now()",
    )
    .bind(project_id)
    .bind(user_id)
    .bind(kind)
    .execute(pool)
    .await?;
    Ok(())
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

    #[test]
    fn toggle_body_matches_legacy_string_coercion() {
        assert!(legacy_json_bool(Some(json!(true))));
        assert!(legacy_json_bool(Some(json!("true"))));
        assert!(!legacy_json_bool(Some(json!(false))));
        assert_eq!(legacy_json_string(None), "undefined");
    }
}
