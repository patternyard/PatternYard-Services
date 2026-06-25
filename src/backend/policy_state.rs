use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct TokenBody {
    token: Option<String>,
}

#[derive(Deserialize)]
struct PolicyUpdateBody {
    token: Option<String>,
    types: Vec<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct PolicyReadResponse {
    #[serde(rename = "privacyPolicy")]
    privacy_policy: Option<i64>,
    #[serde(rename = "TOS")]
    terms: Option<i64>,
    guidelines: Option<i64>,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

#[derive(Clone, Copy)]
enum Policy {
    Privacy,
    Terms,
    Guidelines,
}

impl Policy {
    fn user_column(self) -> &'static str {
        match self {
            Self::Privacy => "last_privacy_policy_read_at",
            Self::Terms => "last_terms_read_at",
            Self::Guidelines => "last_guidelines_read_at",
        }
    }

    fn database_name(self) -> &'static str {
        match self {
            Self::Privacy => "privacy",
            Self::Terms => "terms",
            Self::Guidelines => "guidelines",
        }
    }
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/misc/getLastPolicyRead", get(get_last_policy_read))
        .route(
            "/api/v1/misc/markPrivacyPolicyAsRead",
            post(mark_privacy_policy_as_read),
        )
        .route("/api/v1/misc/markTOSAsRead", post(mark_terms_as_read))
        .route(
            "/api/v1/misc/markGuidelinesAsRead",
            post(mark_guidelines_as_read),
        )
        .route(
            "/api/v1/misc/setLastPolicyUpdate",
            post(set_last_policy_update),
        )
}

async fn get_last_policy_read(
    State(database): State<Database>,
    Query(query): Query<TokenQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, query.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    match sqlx::query_as::<_, PolicyReadResponse>(
        "SELECT \
            floor(extract(epoch FROM last_privacy_policy_read_at) * 1000)::bigint AS privacy_policy, \
            floor(extract(epoch FROM last_terms_read_at) * 1000)::bigint AS terms, \
            floor(extract(epoch FROM last_guidelines_read_at) * 1000)::bigint AS guidelines \
         FROM app.users WHERE id = $1",
    )
    .bind(user.id)
    .fetch_one(pool)
    .await
    {
        Ok(policy_reads) => Json(policy_reads).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn mark_privacy_policy_as_read(
    State(database): State<Database>,
    Json(body): Json<TokenBody>,
) -> Response {
    mark_policy_as_read(database, body.token, Policy::Privacy).await
}

async fn mark_terms_as_read(
    State(database): State<Database>,
    Json(body): Json<TokenBody>,
) -> Response {
    mark_policy_as_read(database, body.token, Policy::Terms).await
}

async fn mark_guidelines_as_read(
    State(database): State<Database>,
    Json(body): Json<TokenBody>,
) -> Response {
    mark_policy_as_read(database, body.token, Policy::Guidelines).await
}

async fn mark_policy_as_read(
    database: Database,
    token: Option<String>,
    policy: Policy,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, token).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let query = format!(
        "UPDATE app.users SET {} = now(), updated_at = now() WHERE id = $1",
        policy.user_column()
    );
    match sqlx::query(&query).bind(user.id).execute(pool).await {
        Ok(_) => success(),
        Err(error) => query_failed(error),
    }
}

async fn set_last_policy_update(
    State(database): State<Database>,
    Json(body): Json<PolicyUpdateBody>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate(pool, body.token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if !user.admin {
        return api_error(StatusCode::FORBIDDEN, "Forbidden");
    }

    let policies = match parse_policies(&body.types) {
        Some(policies) => policies,
        None => return api_error(StatusCode::BAD_REQUEST, "Invalid type"),
    };
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };

    for policy in policies {
        if let Err(error) = sqlx::query(
            "INSERT INTO app.policy_versions (policy, published_at) VALUES ($1, now()) \
             ON CONFLICT (policy) DO UPDATE SET published_at = EXCLUDED.published_at",
        )
        .bind(policy.database_name())
        .execute(&mut *transaction)
        .await
        {
            return query_failed(error);
        }
    }

    match transaction.commit().await {
        Ok(()) => success(),
        Err(error) => query_failed(error),
    }
}

async fn authenticate(
    pool: &PgPool,
    token: Option<String>,
) -> Result<crate::auth::AuthenticatedUser, Response> {
    let token = token.unwrap_or_else(|| "undefined".to_owned());
    match authenticate_token(pool, &token).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(api_error(StatusCode::UNAUTHORIZED, "Reauthenticate")),
        Err(error) => Err(query_failed(error)),
    }
}

fn parse_policies(types: &[String]) -> Option<Vec<Policy>> {
    types
        .iter()
        .map(|policy| match policy.as_str() {
            "privacyPolicy" => Some(Policy::Privacy),
            "tos" => Some(Policy::Terms),
            "guidelines" => Some(Policy::Guidelines),
            _ => None,
        })
        .collect()
}

fn success() -> Response {
    Json(SuccessResponse { success: true }).into_response()
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "policy state query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_names_match_legacy_request_values() {
        let policies = parse_policies(&[
            "privacyPolicy".to_owned(),
            "tos".to_owned(),
            "guidelines".to_owned(),
        ])
        .expect("valid policy names");

        assert_eq!(policies.len(), 3);
        assert!(parse_policies(&["other".to_owned()]).is_none());
    }

    #[test]
    fn policy_read_response_preserves_legacy_keys() {
        let response = PolicyReadResponse {
            privacy_policy: Some(1),
            terms: Some(2),
            guidelines: None,
        };

        assert_eq!(
            serde_json::to_value(response).expect("serializes"),
            serde_json::json!({ "privacyPolicy": 1, "TOS": 2, "guidelines": null })
        );
    }
}
