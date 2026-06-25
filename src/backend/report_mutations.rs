use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Deserialize, Default)]
struct SendReportBody {
    token: Option<String>,
    report: Option<String>,
    target: Option<String>,
    #[serde(rename = "type")]
    report_type: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DeleteReportBody {
    token: Option<String>,
    #[serde(alias = "reportID")]
    report_id: Option<String>,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/reports/sendReport", post(send_report))
        .route("/api/v1/reports/deleteReport", post(delete_report))
}

async fn send_report(
    State(database): State<Database>,
    Json(body): Json<SendReportBody>,
) -> Response {
    let token = legacy_string(body.token);
    let report = legacy_string(body.report);
    let target = legacy_string(body.target).to_lowercase();
    let report_type = legacy_string(body.report_type);
    if report.is_empty() || report_type.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Invalid request");
    }

    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let reporter = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };

    let (report_type_id, reportee_id) = match report_type.as_str() {
        "user" => match user_id_by_username(pool, &target).await {
            Ok(Some(id)) => (0_i16, id),
            Ok(None) => return api_error(StatusCode::NOT_FOUND, "User not found"),
            Err(error) => return query_failed(error),
        },
        "project" => match project_exists(pool, &target).await {
            Ok(true) => (1_i16, target),
            Ok(false) => return api_error(StatusCode::NOT_FOUND, "Project not found"),
            Err(error) => return query_failed(error),
        },
        _ => return api_error(StatusCode::BAD_REQUEST, "Invalid type"),
    };

    match sqlx::query(
        "INSERT INTO app.reports (id, report_type, reportee_id, reporter_id, reason, created_at) \
         VALUES ($1, $2, $3, $4, $5, now()) \
         ON CONFLICT (reporter_id, reportee_id) DO NOTHING",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(report_type_id)
    .bind(reportee_id)
    .bind(reporter.id)
    .bind(report)
    .execute(pool)
    .await
    {
        Ok(_) => Json(SuccessResponse { success: true }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn delete_report(
    State(database): State<Database>,
    Json(body): Json<DeleteReportBody>,
) -> Response {
    let token = legacy_string(body.token);
    let report_id = legacy_string(body.report_id);
    if report_id.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing report ID");
    }

    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let moderator = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };
    if !moderator.admin && !moderator.moderator {
        return api_error(StatusCode::FORBIDDEN, "Unauthorized");
    }

    match sqlx::query("DELETE FROM app.reports WHERE id = $1")
        .bind(report_id)
        .execute(pool)
        .await
    {
        Ok(result) if result.rows_affected() == 0 => {
            api_error(StatusCode::NOT_FOUND, "Report not found")
        }
        Ok(_) => Json(SuccessResponse { success: true }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn user_id_by_username(pool: &PgPool, username: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>("SELECT id FROM app.users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
}

async fn project_exists(pool: &PgPool, project_id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM app.projects WHERE id = $1)")
        .bind(project_id)
        .fetch_one(pool)
        .await
}

fn legacy_string(value: Option<String>) -> String {
    value.unwrap_or_else(|| "undefined".to_owned())
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "report mutation query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_values_match_legacy_string_coercion() {
        assert_eq!(legacy_string(None), "undefined");
        assert_eq!(legacy_string(Some(String::new())), "");
    }

    #[test]
    fn duplicate_report_response_stays_successful() {
        assert_eq!(
            serde_json::to_value(SuccessResponse { success: true }).expect("serializes"),
            serde_json::json!({ "success": true })
        );
    }
}
