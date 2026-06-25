use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, QueryBuilder};

const DEFAULT_PAGE_SIZE: i64 = 20;
const MAX_PAGE_SIZE: i64 = 100;

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PageQuery {
    page: Option<i64>,
    reverse: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectQuery {
    request_type: Option<String>,
    project_id: Option<String>,
}

#[derive(Deserialize, Default)]
struct RandomQuery {
    n: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemixQuery {
    project_id: Option<String>,
    page: Option<i64>,
}

#[derive(Deserialize, Default)]
struct SearchQuery {
    query: Option<String>,
    page: Option<i64>,
    #[serde(rename = "type")]
    sort: Option<String>,
    reverse: Option<bool>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

#[derive(Clone, Copy)]
enum ProjectOrder {
    LastUpdate,
    UploadDate,
    Views,
    Loves,
    Votes,
    Random,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/projects/getproject", get(get_project))
        .route("/api/v1/projects/getprojects", get(get_projects))
        .route(
            "/api/v1/projects/getfeaturedprojects",
            get(get_featured_projects),
        )
        .route(
            "/api/v1/projects/getrandomproject",
            get(get_random_projects),
        )
        .route("/api/v1/projects/getremixes", get(get_remixes))
        .route("/api/v1/projects/searchprojects", get(search_projects))
}

async fn get_project(
    State(database): State<Database>,
    Query(query): Query<ProjectQuery>,
) -> Response {
    if query.request_type.as_deref() != Some("metadata") {
        return api_error(StatusCode::BAD_REQUEST, "Invalid requestType");
    }

    let Some(project_id) = non_empty(query.project_id) else {
        return api_error(StatusCode::BAD_REQUEST, "Missing projectId");
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match fetch_project(pool, &project_id).await {
        Ok(Some(project)) => Json(project).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "Project not found"),
        Err(error) => query_failed(error),
    }
}

async fn get_projects(
    State(database): State<Database>,
    Query(query): Query<PageQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let order = ProjectOrder::LastUpdate;
    let ascending = query.reverse.unwrap_or(false);

    respond_with_projects(
        fetch_projects(
            pool,
            None,
            None,
            false,
            order,
            ascending,
            page(query.page),
            DEFAULT_PAGE_SIZE,
        )
        .await,
    )
}

async fn get_featured_projects(
    State(database): State<Database>,
    Query(query): Query<PageQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    respond_with_projects(
        fetch_projects(
            pool,
            None,
            None,
            true,
            ProjectOrder::UploadDate,
            false,
            page(query.page),
            DEFAULT_PAGE_SIZE,
        )
        .await,
    )
}

async fn get_random_projects(
    State(database): State<Database>,
    Query(query): Query<RandomQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let count = query.n.unwrap_or(1).clamp(0, DEFAULT_PAGE_SIZE);

    respond_with_projects(
        fetch_projects(
            pool,
            None,
            None,
            false,
            ProjectOrder::Random,
            false,
            0,
            count,
        )
        .await,
    )
}

async fn get_remixes(
    State(database): State<Database>,
    Query(query): Query<RemixQuery>,
) -> Response {
    let Some(project_id) = non_empty(query.project_id) else {
        return api_error(StatusCode::BAD_REQUEST, "Missing projectID");
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    respond_with_projects(
        fetch_projects(
            pool,
            None,
            Some(&project_id),
            false,
            ProjectOrder::LastUpdate,
            false,
            page(query.page),
            DEFAULT_PAGE_SIZE,
        )
        .await,
    )
}

async fn search_projects(
    State(database): State<Database>,
    Query(query): Query<SearchQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let order = match query.sort.as_deref() {
        Some("newest") => ProjectOrder::LastUpdate,
        Some("uploaddate") | Some("featured") => ProjectOrder::UploadDate,
        Some("loves") => ProjectOrder::Loves,
        Some("votes") => ProjectOrder::Votes,
        _ => ProjectOrder::Views,
    };

    respond_with_projects(
        fetch_projects(
            pool,
            Some(query.query.as_deref().unwrap_or("")),
            None,
            query.sort.as_deref() == Some("featured"),
            order,
            query.reverse.unwrap_or(false),
            page(query.page),
            DEFAULT_PAGE_SIZE,
        )
        .await,
    )
}

async fn fetch_project(pool: &PgPool, project_id: &str) -> Result<Option<Value>, sqlx::Error> {
    let mut projects = fetch_projects_by_query(
        pool,
        Some(project_id),
        None,
        None,
        false,
        ProjectOrder::LastUpdate,
        false,
        0,
        1,
    )
    .await?;
    Ok(projects.pop())
}

#[allow(clippy::too_many_arguments)]
async fn fetch_projects(
    pool: &PgPool,
    search: Option<&str>,
    remix_of: Option<&str>,
    featured_only: bool,
    order: ProjectOrder,
    ascending: bool,
    page: i64,
    page_size: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    fetch_projects_by_query(
        pool,
        None,
        search,
        remix_of,
        featured_only,
        order,
        ascending,
        page,
        page_size,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn fetch_projects_by_query(
    pool: &PgPool,
    project_id: Option<&str>,
    search: Option<&str>,
    remix_of: Option<&str>,
    featured_only: bool,
    order: ProjectOrder,
    ascending: bool,
    page: i64,
    page_size: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut builder = QueryBuilder::new(
        "SELECT jsonb_build_object(\
            'id', p.legacy_id, \
            'title', p.title, \
            'author', jsonb_build_object('id', u.legacy_id, 'username', u.username), \
            'instructions', p.instructions, \
            'notes', p.notes, \
            'rating', p.rating, \
            'public', p.is_public, \
            'featured', p.is_featured, \
            'loves', p.loves, \
            'votes', p.votes, \
            'views', p.views, \
            'impressions', p.impressions, \
            'date', floor(extract(epoch FROM p.created_at) * 1000)::bigint, \
            'lastUpdate', floor(extract(epoch FROM p.updated_at) * 1000)::bigint, \
            'remix', parent.legacy_id, \
            'fromDonator', false\
        ) \
        FROM projects p \
        JOIN users u ON u.id = p.author_id \
        LEFT JOIN projects parent ON parent.id = p.remix_of \
        WHERE p.is_public = true AND p.moderation_state = 'visible'",
    );

    if let Some(project_id) = project_id {
        builder.push(" AND p.legacy_id = ").push_bind(project_id);
    }
    if let Some(search) = search {
        let pattern = format!("%{search}%");
        builder
            .push(" AND (p.title ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR p.instructions ILIKE ")
            .push_bind(pattern.clone())
            .push(" OR p.notes ILIKE ")
            .push_bind(pattern)
            .push(")");
    }
    if let Some(remix_of) = remix_of {
        builder.push(" AND parent.legacy_id = ").push_bind(remix_of);
    }
    if featured_only {
        builder.push(" AND p.is_featured = true");
    }

    if matches!(order, ProjectOrder::Random) {
        builder.push(" ORDER BY random()");
    } else {
        builder.push(" ORDER BY ");
        builder.push(match order {
            ProjectOrder::LastUpdate => "p.updated_at",
            ProjectOrder::UploadDate => "p.created_at",
            ProjectOrder::Views => "p.views",
            ProjectOrder::Loves => "p.loves",
            ProjectOrder::Votes => "p.votes",
            ProjectOrder::Random => unreachable!(),
        });
        builder.push(if ascending { " ASC" } else { " DESC" });
        builder.push(", p.id ASC");
    }

    builder
        .push(" LIMIT ")
        .push_bind(page_size.clamp(0, MAX_PAGE_SIZE))
        .push(" OFFSET ")
        .push_bind(page.saturating_mul(page_size));

    builder.build_query_scalar::<Value>().fetch_all(pool).await
}

fn page(value: Option<i64>) -> i64 {
    value.unwrap_or(0).max(0)
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty() && value != "undefined")
}

fn respond_with_projects(result: Result<Vec<Value>, sqlx::Error>) -> Response {
    match result {
        Ok(projects) => Json(projects).into_response(),
        Err(error) => query_failed(error),
    }
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "public project query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_is_never_negative() {
        assert_eq!(page(None), 0);
        assert_eq!(page(Some(-3)), 0);
        assert_eq!(page(Some(4)), 4);
    }

    #[test]
    fn missing_query_values_are_rejected() {
        assert_eq!(non_empty(None), None);
        assert_eq!(non_empty(Some(String::new())), None);
        assert_eq!(non_empty(Some("undefined".into())), None);
        assert_eq!(non_empty(Some("42".into())), Some("42".into()));
    }
}
