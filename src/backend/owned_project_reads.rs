use crate::auth::{AuthenticatedUser, authenticate_token};
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;

const PAGE_SIZE: i64 = 20;

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ProjectsQuery {
    token: Option<String>,
    author_username: Option<String>,
    page: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct AuthorAccess {
    id: String,
    private_profile: bool,
    allow_following_view: bool,
}

#[derive(serde::Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/projects/getmyprojects", get(get_my_projects))
        .route(
            "/api/v1/projects/getprojectsbyauthor",
            get(get_projects_by_author),
        )
}

async fn get_my_projects(
    State(database): State<Database>,
    Query(query): Query<ProjectsQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, query.token, StatusCode::UNAUTHORIZED).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "Reauthenticate"),
        Err(response) => return response,
    };

    respond(fetch_projects(pool, &user.id, query.page, true).await)
}

async fn get_projects_by_author(
    State(database): State<Database>,
    Query(query): Query<ProjectsQuery>,
) -> Response {
    let author_username = legacy_author_username(query.author_username);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let author = match author_by_username(pool, &author_username).await {
        Ok(Some(author)) => author,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "User not found"),
        Err(error) => return query_failed(error),
    };
    let viewer = match authenticate(pool, query.token, StatusCode::UNAUTHORIZED).await {
        Ok(viewer) => viewer,
        Err(response) => return response,
    };

    if author.private_profile && !can_view_private_profile(pool, &author, viewer.as_ref()).await {
        return api_error(StatusCode::FORBIDDEN, "PrivateProfile");
    }

    match fetch_projects(pool, &author.id, query.page, false).await {
        Ok(projects) => {
            if let Err(error) = add_impressions(pool, &projects).await {
                return query_failed(error);
            }
            Json(projects).into_response()
        }
        Err(error) => query_failed(error),
    }
}

async fn authenticate(
    pool: &PgPool,
    token: Option<String>,
    _status: StatusCode,
) -> Result<Option<AuthenticatedUser>, Response> {
    let token = token.unwrap_or_else(|| "undefined".to_owned());
    authenticate_token(pool, &token).await.map_err(query_failed)
}

async fn author_by_username(
    pool: &PgPool,
    username: &str,
) -> Result<Option<AuthorAccess>, sqlx::Error> {
    sqlx::query_as::<_, AuthorAccess>(
        "SELECT id, private_profile, allow_following_view \
         FROM app.users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
}

async fn can_view_private_profile(
    pool: &PgPool,
    author: &AuthorAccess,
    viewer: Option<&AuthenticatedUser>,
) -> bool {
    let Some(viewer) = viewer else {
        return false;
    };
    if viewer.id == author.id || viewer.admin || viewer.moderator {
        return true;
    }
    if !author.allow_following_view {
        return false;
    }

    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM app.follows \
         WHERE follower_id = $1 AND target_id = $2 AND active)",
    )
    .bind(&viewer.id)
    .bind(&author.id)
    .fetch_one(pool)
    .await
    .unwrap_or(false)
}

async fn fetch_projects(
    pool: &PgPool,
    author_id: &str,
    page: Option<i64>,
    include_private: bool,
) -> Result<Vec<Value>, sqlx::Error> {
    sqlx::query_scalar::<_, Value>(
        "SELECT jsonb_build_object(\
            'id', p.id, 'title', p.title, \
            'author', jsonb_build_object('id', u.id, 'username', u.username), \
            'instructions', p.instructions, 'notes', p.notes, 'rating', p.rating, \
            'public', p.is_public, 'featured', p.featured, \
            'softRejected', p.soft_rejected, 'hardReject', p.hard_rejected, \
            'noFeature', p.no_feature, 'modMessage', p.moderation_message, \
            'loves', p.loves, 'votes', p.votes, 'views', p.views, \
            'impressions', p.impressions, \
            'date', floor(extract(epoch FROM p.created_at) * 1000)::bigint, \
            'lastUpdate', floor(extract(epoch FROM p.updated_at) * 1000)::bigint, \
            'remix', p.remix_of_id, 'fromDonator', 'donator' = ANY(u.badges)) \
         FROM app.projects p JOIN app.users u ON u.id = p.author_id \
         WHERE p.author_id = $1 AND NOT p.hard_rejected \
           AND ($2 OR (p.is_public AND NOT p.soft_rejected)) \
         ORDER BY p.updated_at DESC, p.id ASC LIMIT $3 OFFSET $4",
    )
    .bind(author_id)
    .bind(include_private)
    .bind(PAGE_SIZE)
    .bind(page_offset(page))
    .fetch_all(pool)
    .await
}

fn legacy_author_username(author_username: Option<String>) -> String {
    author_username
        .unwrap_or_else(|| "undefined".to_owned())
        .to_lowercase()
}

fn page_offset(page: Option<i64>) -> i64 {
    page.unwrap_or(0).max(0).saturating_mul(PAGE_SIZE)
}

async fn add_impressions(pool: &PgPool, projects: &[Value]) -> Result<(), sqlx::Error> {
    let ids: Vec<&str> = projects
        .iter()
        .filter_map(|project| project.get("id").and_then(Value::as_str))
        .collect();
    if !ids.is_empty() {
        sqlx::query("UPDATE app.projects SET impressions = impressions + 1 WHERE id = ANY($1)")
            .bind(ids)
            .execute(pool)
            .await?;
    }
    Ok(())
}

fn respond(result: Result<Vec<Value>, sqlx::Error>) -> Response {
    match result {
        Ok(projects) => Json(projects).into_response(),
        Err(error) => query_failed(error),
    }
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "owned project read query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, error: &'static str) -> Response {
    (status, Json(ErrorBody { error })).into_response()
}

#[cfg(test)]
mod tests {
    use super::{legacy_author_username, page_offset};

    #[test]
    fn negative_pages_are_clamped_by_fetch_contract() {
        assert_eq!(page_offset(Some(-4)), 0);
    }

    #[test]
    fn missing_author_matches_legacy_string_coercion() {
        assert_eq!(legacy_author_username(None), "undefined");
    }
}
