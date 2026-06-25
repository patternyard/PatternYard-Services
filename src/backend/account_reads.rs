use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct TargetQuery {
    target: Option<String>,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(Serialize)]
struct CustomizationResponse {
    customization: String,
}

#[derive(sqlx::FromRow)]
struct CustomizationRecord {
    badges: Vec<String>,
    disabled: Option<bool>,
    settings: Option<Value>,
}

#[derive(sqlx::FromRow)]
struct AccountRecord {
    id: String,
    username: String,
    real_username: String,
    admin: bool,
    moderator: bool,
    permanently_banned: bool,
    currently_banned: bool,
    badges: Vec<String>,
    rank: i32,
    featured_project_id: Option<String>,
    featured_project_title: Option<String>,
    follower_count: i32,
    can_request_rank_up: bool,
    last_privacy_policy_read: Option<String>,
    last_terms_read: Option<String>,
    last_guidelines_read: Option<String>,
    private_profile: bool,
    allow_following_view: bool,
    email: Option<String>,
    email_verified: bool,
    birthday_entered: bool,
    country_entered: bool,
    country: Option<String>,
    login_methods: Vec<String>,
}

#[derive(Serialize)]
struct LastPolicyRead {
    #[serde(rename = "privacyPolicy")]
    privacy_policy: Option<String>,
    #[serde(rename = "TOS")]
    terms: Option<String>,
    guidelines: Option<String>,
}

#[derive(Serialize)]
struct AccountResponse {
    id: String,
    username: String,
    real_username: String,
    admin: bool,
    approver: bool,
    #[serde(rename = "isBanned")]
    is_banned: bool,
    badges: Vec<String>,
    donator: bool,
    rank: i32,
    #[serde(rename = "myFeaturedProject")]
    my_featured_project: String,
    #[serde(rename = "myFeaturedProjectTitle")]
    my_featured_project_title: String,
    followers: i32,
    canrankup: bool,
    viewable: bool,
    #[serde(rename = "loginMethods")]
    login_methods: Vec<String>,
    #[serde(rename = "lastPolicyRead")]
    last_policy_read: LastPolicyRead,
    #[serde(rename = "privateProfile")]
    private_profile: bool,
    #[serde(rename = "canFollowingSeeProfile")]
    can_following_see_profile: bool,
    standing: i32,
    email: Option<String>,
    #[serde(rename = "isEmailVerified")]
    is_email_verified: bool,
    #[serde(rename = "birthdayEntered")]
    birthday_entered: bool,
    #[serde(rename = "countryEntered")]
    country_entered: bool,
    country: Option<String>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/users/tokenlogin", get(token_login))
        .route("/api/v1/users/userfromcode", get(user_from_code))
        .route(
            "/api/v1/users/customization/getCustomization",
            get(get_customization),
        )
}

async fn token_login(
    State(database): State<Database>,
    Query(query): Query<TokenQuery>,
) -> Response {
    let token = legacy_string(query.token);
    if token.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing token");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match authenticate_token(pool, &token).await {
        Ok(Some(_)) => Json(SuccessResponse { success: true }).into_response(),
        Ok(None) => api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => query_failed(error),
    }
}

async fn user_from_code(
    State(database): State<Database>,
    Query(query): Query<TokenQuery>,
) -> Response {
    let token = legacy_string(query.token);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };

    match sqlx::query_as::<_, AccountRecord>(
        "SELECT u.id, u.username::text AS username, u.display_username AS real_username, \
         u.admin, u.moderator, u.permanently_banned, \
         COALESCE(u.unban_at > now(), false) AS currently_banned, u.badges, u.rank, \
         u.featured_project_id, u.featured_project_title, u.follower_count, \
         ((((SELECT count(*) FROM app.projects p WHERE p.author_id = u.id) >= 3 \
            AND u.first_login_at <= now() - interval '5 days') OR cardinality(u.badges) > 0) \
           AND u.rank = 0) AS can_request_rank_up, \
         to_jsonb(u.last_privacy_policy_read_at)#>>'{}' AS last_privacy_policy_read, \
         to_jsonb(u.last_terms_read_at)#>>'{}' AS last_terms_read, \
         to_jsonb(u.last_guidelines_read_at)#>>'{}' AS last_guidelines_read, \
         u.private_profile, u.allow_following_view, d.email::text AS email, \
         u.email_verified, u.birthday_entered, u.country_entered, d.country_code AS country, \
         COALESCE((SELECT array_agg(provider ORDER BY provider) \
                   FROM app.oauth_identities WHERE user_id = u.id), '{}') \
         || CASE WHEN u.password_hash <> '' THEN ARRAY['password']::text[] ELSE '{}' END \
         AS login_methods \
         FROM app.users u LEFT JOIN app.user_private_details d ON d.user_id = u.id \
         WHERE u.id = $1",
    )
    .bind(user.id)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(record)) => Json(account_response(record)).into_response(),
        Ok(None) => api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => query_failed(error),
    }
}

fn account_response(record: AccountRecord) -> AccountResponse {
    let is_banned = record.permanently_banned || record.currently_banned;
    let standing = if record.currently_banned {
        2
    } else if record.permanently_banned {
        3
    } else {
        0
    };
    AccountResponse {
        id: record.id,
        username: record.username,
        real_username: record.real_username,
        admin: record.admin,
        approver: record.moderator,
        is_banned,
        donator: record.badges.iter().any(|badge| badge == "donator"),
        badges: record.badges,
        rank: record.rank,
        my_featured_project: record.featured_project_id.unwrap_or_default(),
        my_featured_project_title: record.featured_project_title.unwrap_or_default(),
        followers: record.follower_count,
        canrankup: record.can_request_rank_up,
        viewable: false,
        login_methods: record.login_methods,
        last_policy_read: LastPolicyRead {
            privacy_policy: record.last_privacy_policy_read,
            terms: record.last_terms_read,
            guidelines: record.last_guidelines_read,
        },
        private_profile: record.private_profile,
        can_following_see_profile: record.allow_following_view,
        standing,
        email: record.email,
        is_email_verified: record.email_verified,
        birthday_entered: record.birthday_entered,
        country_entered: record.country_entered,
        country: record.country,
    }
}

async fn get_customization(
    State(database): State<Database>,
    Query(query): Query<TargetQuery>,
) -> Response {
    let target = legacy_string(query.target).to_lowercase();
    if target.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing target");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_as::<_, CustomizationRecord>(
        "SELECT u.badges, c.disabled, c.settings \
         FROM app.users u \
         LEFT JOIN app.account_customizations c ON c.user_id = u.id \
         WHERE u.username = $1",
    )
    .bind(target)
    .fetch_optional(pool)
    .await
    {
        Ok(None) => api_error(StatusCode::NOT_FOUND, "User does not exist"),
        Ok(Some(record)) if !record.badges.iter().any(|badge| badge == "donator") => {
            api_error(StatusCode::BAD_REQUEST, "NotDonator")
        }
        Ok(Some(record)) => {
            let customization = if record.disabled.unwrap_or(false) {
                "{}".to_owned()
            } else {
                record
                    .settings
                    .map(|settings| settings.to_string())
                    .unwrap_or_else(|| "{}".to_owned())
            };
            Json(CustomizationResponse { customization }).into_response()
        }
        Err(error) => query_failed(error),
    }
}

fn legacy_string(value: Option<String>) -> String {
    value.unwrap_or_else(|| "undefined".to_owned())
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "account read query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_legacy_string_coercion() {
        assert_eq!(legacy_string(None), "undefined");
        assert_eq!(legacy_string(Some(String::new())), "");
    }

    #[test]
    fn customization_remains_stringified_json() {
        let response = CustomizationResponse {
            customization: serde_json::json!({ "theme": "calm" }).to_string(),
        };
        assert_eq!(
            serde_json::to_value(response).expect("serializes"),
            serde_json::json!({ "customization": "{\"theme\":\"calm\"}" })
        );
    }

    #[test]
    fn account_response_preserves_ban_standing_and_login_methods() {
        let response = account_response(AccountRecord {
            id: "user-1".into(),
            username: "sample".into(),
            real_username: "Sample".into(),
            admin: false,
            moderator: false,
            permanently_banned: false,
            currently_banned: true,
            badges: vec!["donator".into()],
            rank: 0,
            featured_project_id: None,
            featured_project_title: None,
            follower_count: 3,
            can_request_rank_up: true,
            last_privacy_policy_read: None,
            last_terms_read: None,
            last_guidelines_read: None,
            private_profile: false,
            allow_following_view: false,
            email: None,
            email_verified: false,
            birthday_entered: false,
            country_entered: false,
            country: None,
            login_methods: vec!["github".into(), "password".into()],
        });
        assert!(response.is_banned);
        assert_eq!(response.standing, 2);
        assert!(response.donator);
        assert_eq!(response.login_methods, vec!["github", "password"]);
    }
}
