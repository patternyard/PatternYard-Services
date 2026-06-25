use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
struct UsernameQuery {
    username: Option<String>,
}

#[derive(Deserialize)]
struct ProfileQuery {
    target: Option<String>,
    token: Option<String>,
}

#[derive(Deserialize)]
struct IdQuery {
    #[serde(rename = "ID", alias = "id")]
    id: Option<String>,
}

#[derive(Deserialize)]
struct ProjectCountBody {
    target: Option<String>,
}

#[derive(Serialize)]
struct ExistsResponse {
    exists: bool,
}

#[derive(Serialize)]
struct IdResponse {
    id: String,
}

#[derive(Serialize)]
struct BadgesResponse {
    badges: Vec<String>,
}

#[derive(Serialize)]
struct CountResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct ProfileRecord {
    id: String,
    real_username: String,
    badges: Vec<String>,
    rank: i32,
    bio: String,
    featured_project_id: Option<String>,
    featured_project_title: Option<String>,
    follower_count: i32,
    private_profile: bool,
    allow_following_view: bool,
    permanently_banned: bool,
    currently_banned: bool,
    can_request_rank_up: bool,
}

#[derive(Serialize)]
struct ProfileResponse {
    success: bool,
    id: String,
    username: String,
    real_username: String,
    badges: Vec<String>,
    donator: bool,
    rank: i32,
    bio: String,
    #[serde(rename = "myFeaturedProject")]
    my_featured_project: String,
    #[serde(rename = "myFeaturedProjectTitle")]
    my_featured_project_title: String,
    followers: i32,
    canrankup: bool,
    #[serde(rename = "privateProfile")]
    private_profile: bool,
    #[serde(rename = "canFollowingSeeProfile")]
    can_following_see_profile: bool,
    #[serde(rename = "isFollowing")]
    is_following: bool,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/users/userexists", get(user_exists))
        .route("/api/v1/users/getid", get(get_id))
        .route("/api/v1/users/getusername", get(get_username))
        .route("/api/v1/users/getBadges", get(get_badges))
        .route("/api/v1/users/profile", get(get_profile))
        .route(
            "/api/v1/users/meta/getfollowercount",
            get(get_follower_count),
        )
        .route(
            "/api/v1/users/getprojectcountofuser",
            post(get_project_count),
        )
}

async fn user_exists(
    State(database): State<Database>,
    Query(query): Query<UsernameQuery>,
) -> Response {
    let username = legacy_username(query.username);
    if username.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM app.users WHERE username = $1)",
    )
    .bind(username)
    .fetch_one(pool)
    .await
    {
        Ok(exists) => Json(ExistsResponse { exists }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_id(State(database): State<Database>, Query(query): Query<UsernameQuery>) -> Response {
    let username = legacy_username(query.username);
    if username.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, String>("SELECT id FROM app.users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(id)) => Json(IdResponse { id }).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "UserNotFound"),
        Err(error) => query_failed(error),
    }
}

async fn get_username(State(database): State<Database>, Query(query): Query<IdQuery>) -> Response {
    let id = legacy_string(query.id);
    if id.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing ID");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, String>("SELECT username::text FROM app.users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(username)) => Json(json!({ "username": username })).into_response(),
        Ok(None) => Json(json!({ "username": false })).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_badges(
    State(database): State<Database>,
    Query(query): Query<UsernameQuery>,
) -> Response {
    let username = legacy_username(query.username);
    if username.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, Vec<String>>("SELECT badges FROM app.users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(badges)) => Json(BadgesResponse { badges }).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "NotFound"),
        Err(error) => query_failed(error),
    }
}

async fn get_follower_count(
    State(database): State<Database>,
    Query(query): Query<UsernameQuery>,
) -> Response {
    let username = legacy_username(query.username);
    if username.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing username");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, i32>("SELECT follower_count FROM app.users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
    {
        Ok(count) => Json(CountResponse {
            count: count.map(i64::from),
        })
        .into_response(),
        Err(error) => query_failed(error),
    }
}

async fn get_profile(
    State(database): State<Database>,
    Query(query): Query<ProfileQuery>,
) -> Response {
    let target = legacy_username(query.target);
    let token = legacy_string(query.token);
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let viewer = match authenticate_token(pool, &token).await {
        Ok(viewer) => viewer,
        Err(error) => return query_failed(error),
    };

    let record = match sqlx::query_as::<_, ProfileRecord>(
        "SELECT id, display_username AS real_username, badges, rank, bio, \
         featured_project_id, featured_project_title, follower_count, \
         private_profile, allow_following_view, permanently_banned, \
         COALESCE(unban_at > now(), false) AS currently_banned, \
         (((SELECT count(*) FROM app.projects p \
             WHERE p.author_id = u.id AND p.is_public \
               AND NOT p.soft_rejected AND NOT p.hard_rejected) >= 3 \
            AND first_login_at <= now() - interval '5 days') \
           OR cardinality(badges) > 0) AS can_request_rank_up \
         FROM app.users u WHERE username = $1",
    )
    .bind(&target)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "NotFound"),
        Err(error) => return query_failed(error),
    };

    let viewer_is_target = viewer
        .as_ref()
        .is_some_and(|viewer| viewer.username.eq_ignore_ascii_case(&target));
    let viewer_is_mod = viewer
        .as_ref()
        .is_some_and(|viewer| viewer.admin || viewer.moderator);
    if (record.permanently_banned || record.currently_banned) && !viewer_is_target && !viewer_is_mod
    {
        return api_error(StatusCode::NOT_FOUND, "NotFound");
    }

    let is_following = match &viewer {
        Some(viewer) => match follows(pool, &viewer.id, &record.id).await {
            Ok(value) => value,
            Err(error) => return query_failed(error),
        },
        None => false,
    };
    let may_view = !record.private_profile
        || viewer_is_target
        || viewer_is_mod
        || (is_following && record.allow_following_view);

    Json(profile_response(target, record, is_following, may_view)).into_response()
}

fn profile_response(
    username: String,
    record: ProfileRecord,
    is_following: bool,
    may_view: bool,
) -> ProfileResponse {
    ProfileResponse {
        success: may_view,
        id: record.id,
        username,
        real_username: record.real_username,
        badges: if may_view {
            record.badges.clone()
        } else {
            Vec::new()
        },
        donator: may_view && record.badges.iter().any(|badge| badge == "donator"),
        rank: if may_view { record.rank } else { 0 },
        bio: if may_view { record.bio } else { String::new() },
        my_featured_project: if may_view {
            record.featured_project_id.unwrap_or_default()
        } else {
            String::new()
        },
        my_featured_project_title: if may_view {
            record.featured_project_title.unwrap_or_default()
        } else {
            String::new()
        },
        followers: if may_view { record.follower_count } else { 0 },
        canrankup: may_view && record.can_request_rank_up && record.rank != 1,
        private_profile: record.private_profile,
        can_following_see_profile: record.allow_following_view,
        is_following,
    }
}

async fn follows(
    pool: &sqlx::PgPool,
    follower_id: &str,
    target_id: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM app.follows \
         WHERE follower_id = $1 AND target_id = $2 AND active)",
    )
    .bind(follower_id)
    .bind(target_id)
    .fetch_one(pool)
    .await
}

async fn get_project_count(
    State(database): State<Database>,
    Json(body): Json<ProjectCountBody>,
) -> Response {
    let target = legacy_username(body.target);
    if target.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing target");
    }
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };

    match sqlx::query_scalar::<_, i64>(
        "SELECT count(p.id) FROM app.users u LEFT JOIN app.projects p ON p.author_id = u.id WHERE u.username = $1 GROUP BY u.id",
    )
    .bind(target)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(count)) => Json(CountResponse { count: Some(count) }).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "User does not exist"),
        Err(error) => query_failed(error),
    }
}

fn legacy_string(value: Option<String>) -> String {
    value.unwrap_or_else(|| "undefined".to_owned())
}

fn legacy_username(value: Option<String>) -> String {
    legacy_string(value).to_lowercase()
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "public user query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_legacy_string_coercion() {
        assert_eq!(legacy_username(Some("NewUser".into())), "newuser");
        assert_eq!(legacy_username(None), "undefined");
        assert_eq!(
            legacy_string(Some("CaseSensitiveID".into())),
            "CaseSensitiveID"
        );
        assert_eq!(legacy_string(None), "undefined");
    }

    #[test]
    fn missing_follower_count_serializes_as_empty_object() {
        let response = serde_json::to_value(CountResponse { count: None }).expect("serializes");
        assert_eq!(response, serde_json::Value::Object(Default::default()));
    }

    #[test]
    fn private_profile_redacts_details_but_preserves_identity() {
        let response = profile_response(
            "sample".into(),
            ProfileRecord {
                id: "user-1".into(),
                real_username: "Sample".into(),
                badges: vec!["donator".into()],
                rank: 2,
                bio: "private".into(),
                featured_project_id: Some("project-1".into()),
                featured_project_title: Some("4".into()),
                follower_count: 12,
                private_profile: true,
                allow_following_view: false,
                permanently_banned: false,
                currently_banned: false,
                can_request_rank_up: true,
            },
            false,
            false,
        );
        assert!(!response.success);
        assert_eq!(response.id, "user-1");
        assert!(response.badges.is_empty());
        assert!(response.bio.is_empty());
        assert_eq!(response.followers, 0);
    }
}
