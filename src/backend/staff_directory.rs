use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct StaffMember {
    id: String,
    username: String,
}

#[derive(Serialize)]
struct AdminsResponse {
    admins: Vec<StaffMember>,
}

#[derive(Serialize)]
struct ModeratorsResponse {
    mods: Vec<StaffMember>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

#[derive(Clone, Copy)]
enum StaffRole {
    Administrator,
    Moderator,
}

impl StaffRole {
    fn column(self) -> &'static str {
        match self {
            Self::Administrator => "admin",
            Self::Moderator => "moderator",
        }
    }
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/users/getadmins", get(get_admins))
        .route("/api/v1/users/getmods", get(get_moderators))
}

async fn get_admins(State(database): State<Database>, Query(query): Query<TokenQuery>) -> Response {
    match get_staff(database, query.token, StaffRole::Administrator).await {
        Ok(admins) => Json(AdminsResponse { admins }).into_response(),
        Err(response) => response,
    }
}

async fn get_moderators(
    State(database): State<Database>,
    Query(query): Query<TokenQuery>,
) -> Response {
    match get_staff(database, query.token, StaffRole::Moderator).await {
        Ok(mods) => Json(ModeratorsResponse { mods }).into_response(),
        Err(response) => response,
    }
}

async fn get_staff(
    database: Database,
    token: Option<String>,
    role: StaffRole,
) -> Result<Vec<StaffMember>, Response> {
    let Some(pool) = database.pool() else {
        return Err(database_unavailable());
    };
    authenticate_admin(pool, token).await?;

    let query = format!(
        "SELECT id, username::text AS username FROM app.users \
         WHERE {} = true ORDER BY lower(username::text), id",
        role.column()
    );
    sqlx::query_as::<_, StaffMember>(&query)
        .fetch_all(pool)
        .await
        .map_err(query_failed)
}

async fn authenticate_admin(pool: &PgPool, token: Option<String>) -> Result<(), Response> {
    let token = token.unwrap_or_else(|| "undefined".to_owned());
    match authenticate_token(pool, &token).await {
        Ok(Some(user)) if user.admin => Ok(()),
        Ok(Some(_)) => Err(api_error(StatusCode::UNAUTHORIZED, "Unauthorized")),
        Ok(None) => Err(api_error(StatusCode::BAD_REQUEST, "Reauthenticate")),
        Err(error) => Err(query_failed(error)),
    }
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "staff directory query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_responses_preserve_legacy_keys() {
        let member = StaffMember {
            id: "member-id".to_owned(),
            username: "member".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(AdminsResponse {
                admins: vec![member]
            })
            .expect("serializes"),
            serde_json::json!({
                "admins": [{ "id": "member-id", "username": "member" }]
            })
        );

        assert_eq!(
            serde_json::to_value(ModeratorsResponse { mods: Vec::new() }).expect("serializes"),
            serde_json::json!({ "mods": [] })
        );
    }

    #[test]
    fn role_columns_are_fixed_identifiers() {
        assert_eq!(StaffRole::Administrator.column(), "admin");
        assert_eq!(StaffRole::Moderator.column(), "moderator");
    }
}
