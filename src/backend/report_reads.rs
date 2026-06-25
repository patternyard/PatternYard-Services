use crate::auth::{AuthenticatedUser, authenticate_token};
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

const PAGE_SIZE: i64 = 20;

#[derive(Deserialize, Default)]
struct ReportsQuery {
    token: Option<String>,
    #[serde(rename = "type")]
    report_type: Option<String>,
    target: Option<String>,
    page: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct LegacyReport {
    reporter: String,
    target: String,
    #[serde(rename = "targetID")]
    target_id: String,
    report: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    author: Option<String>,
    date: i64,
    #[serde(rename = "type")]
    report_type: String,
    id: String,
}

#[derive(Serialize)]
struct ReportsResponse {
    reports: Vec<LegacyReport>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/reports/getReports", get(get_reports))
        .route(
            "/api/v1/reports/getReportsByTarget",
            get(get_reports_by_target),
        )
}

async fn get_reports(
    State(database): State<Database>,
    Query(query): Query<ReportsQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = authenticate_moderator(pool, query.token).await {
        return response;
    }
    let page = query.page.unwrap_or(0).max(0);
    let report_type = query.report_type.unwrap_or_else(|| "undefined".to_owned());
    let type_filter = (!report_type.is_empty()).then_some(report_type.as_str());

    match fetch_reports(pool, type_filter, None, page, true).await {
        Ok(reports) => Json(ReportsResponse { reports }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_reports_by_target(
    State(database): State<Database>,
    Query(query): Query<ReportsQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = authenticate_moderator(pool, query.token).await {
        return response;
    }
    let target = query.target.unwrap_or_else(|| "undefined".to_owned());
    let page = query.page.unwrap_or(0).max(0);
    let target_id = match resolve_target(pool, &target).await {
        Ok(Some(target_id)) => target_id,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "Target not found"),
        Err(error) => return query_failed(error),
    };

    match fetch_reports(pool, None, Some(&target_id), page, false).await {
        Ok(reports) => Json(ReportsResponse { reports }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn authenticate_moderator(
    pool: &PgPool,
    token: Option<String>,
) -> Result<AuthenticatedUser, Response> {
    let token = token.unwrap_or_else(|| "undefined".to_owned());
    match authenticate_token(pool, &token).await {
        Ok(Some(user)) if user.admin || user.moderator => Ok(user),
        Ok(Some(_)) => Err(api_error(StatusCode::FORBIDDEN, "Unauthorized")),
        Ok(None) => Err(api_error(StatusCode::UNAUTHORIZED, "Reauthenticate")),
        Err(error) => Err(query_failed(error)),
    }
}

async fn resolve_target(pool: &PgPool, target: &str) -> Result<Option<String>, sqlx::Error> {
    if let Some(user_id) =
        sqlx::query_scalar::<_, String>("SELECT id FROM app.users WHERE username = $1")
            .bind(target)
            .fetch_optional(pool)
            .await?
    {
        return Ok(Some(user_id));
    }

    sqlx::query_scalar::<_, String>("SELECT id FROM app.projects WHERE id = $1")
        .bind(target)
        .fetch_optional(pool)
        .await
}

async fn fetch_reports(
    pool: &PgPool,
    type_filter: Option<&str>,
    target_filter: Option<&str>,
    page: i64,
    include_author: bool,
) -> Result<Vec<LegacyReport>, sqlx::Error> {
    sqlx::query_as::<_, LegacyReport>(
        "SELECT reporter.username AS reporter, \
            CASE WHEN reports.report_type = 0 THEN COALESCE(target_user.username, reports.reportee_id) ELSE project.title END AS target, \
            reports.reportee_id AS target_id, reports.reason AS report, \
            CASE WHEN $3 THEN COALESCE(author.username, '') ELSE NULL END AS author, \
            floor(extract(epoch FROM reports.created_at) * 1000)::bigint AS date, \
            CASE reports.report_type WHEN 0 THEN 'user' ELSE 'project' END AS report_type, \
            reports.id \
         FROM app.reports reports \
         JOIN app.users reporter ON reporter.id = reports.reporter_id \
         LEFT JOIN app.users target_user ON reports.report_type = 0 AND target_user.id = reports.reportee_id \
         LEFT JOIN app.projects project ON reports.report_type = 1 AND project.id = reports.reportee_id \
         LEFT JOIN app.users author ON author.id = project.author_id \
         WHERE ($1::text IS NULL OR CASE reports.report_type WHEN 0 THEN 'user' ELSE 'project' END = $1) \
           AND ($2::text IS NULL OR reports.reportee_id = $2) \
           AND (reports.report_type = 0 OR project.id IS NOT NULL) \
         ORDER BY reports.created_at DESC, reports.id DESC \
         LIMIT $4 OFFSET $5",
    )
    .bind(type_filter)
    .bind(target_filter)
    .bind(include_author)
    .bind(PAGE_SIZE)
    .bind(page.saturating_mul(PAGE_SIZE))
    .fetch_all(pool)
    .await
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "report read query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, error: &'static str) -> Response {
    (status, Json(ErrorBody { error })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_shape_preserves_legacy_names() {
        let report = LegacyReport {
            reporter: "reporter".to_owned(),
            target: "project".to_owned(),
            target_id: "project-1".to_owned(),
            report: "reason".to_owned(),
            author: Some("author".to_owned()),
            date: 1,
            report_type: "project".to_owned(),
            id: "report-1".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(report).expect("serializable")["targetID"],
            "project-1"
        );
    }

    #[test]
    fn target_response_omits_author() {
        let report = LegacyReport {
            reporter: "reporter".to_owned(),
            target: "user".to_owned(),
            target_id: "user-1".to_owned(),
            report: "reason".to_owned(),
            author: None,
            date: 1,
            report_type: "user".to_owned(),
            id: "report-1".to_owned(),
        };
        assert!(serde_json::to_value(report).expect("serializable")["author"].is_null());
    }
}
