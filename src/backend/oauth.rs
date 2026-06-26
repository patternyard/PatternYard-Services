use crate::auth::authenticate_token;
use crate::backend::session_writes::{create_session_executor, hash_password};
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};
use std::env;

const API_URL: &str = "https://api.patternyard.dev";
const HOME_URL: &str = "https://patternyard.dev";
const FLOW_TTL_SECONDS: u16 = 300;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Provider {
    Scratch,
    Github,
    Google,
}

impl Provider {
    fn parse(value: Option<String>) -> Option<Self> {
        match value.as_deref() {
            Some("scratch") => Some(Self::Scratch),
            Some("github") => Some(Self::Github),
            Some("google") => Some(Self::Google),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Scratch => "scratch",
            Self::Github => "github",
            Self::Google => "google",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FlowKind {
    Login,
    CreateAccount,
    AddMethod,
    AddPassword,
}

#[derive(Deserialize, Serialize)]
struct OAuthFlow {
    provider: Provider,
    kind: FlowKind,
    user_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct PasswordTicket {
    user_id: String,
    provider: Provider,
    provider_subject: String,
}

#[derive(Deserialize, Default)]
struct StartQuery {
    method: Option<String>,
    token: Option<String>,
}

#[derive(Deserialize, Default)]
struct CallbackQuery {
    state: Option<String>,
    code: Option<String>,
}

#[derive(Deserialize, Default)]
struct SuccessQuery {
    token: Option<String>,
    username: Option<String>,
}

#[derive(Deserialize, Default)]
struct ScratchPasswordQuery {
    at: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize, Default)]
struct PasswordBody {
    at: Option<Value>,
    password: Option<Value>,
}

#[derive(Deserialize, Default)]
struct RemoveMethodBody {
    method: Option<Value>,
    token: Option<Value>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

#[derive(Serialize)]
struct SuccessBody {
    success: bool,
}

#[derive(Serialize)]
struct PasswordResponse {
    token: String,
    username: String,
}

#[derive(Debug)]
struct ProviderProfile {
    subject: String,
    suggested_username: String,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/users/addoauthmethod", get(add_oauth_method))
        .route("/api/v1/users/addpasswordtooauth", get(add_password))
        .route(
            "/api/v1/users/createoauthaccount",
            get(create_oauth_account),
        )
        .route("/api/v1/users/loginoauthaccount", get(login_oauth_account))
        .route("/api/v1/users/removeoauthmethod", post(remove_oauth_method))
        .route("/api/v1/users/sendloginsuccess", get(send_login_success))
        .route("/api/v1/users/addscratchlogin", get(scratch_add_method))
        .route(
            "/api/v1/users/scratchaddpassword",
            get(scratch_add_password),
        )
        .route(
            "/api/v1/users/scratchaddpasswordfinal",
            get(scratch_add_password_final),
        )
        .route("/api/v1/users/scratchoauthcreate", get(scratch_create))
        .route("/api/v1/users/scratchoauthlogin", get(scratch_login))
        .route(
            "/api/v1/users/githubcallback/addmethod",
            get(github_add_method),
        )
        .route(
            "/api/v1/users/githubcallback/addpassword",
            get(github_add_password),
        )
        .route(
            "/api/v1/users/githubcallback/addpasswordfinal",
            post(github_add_password_final),
        )
        .route(
            "/api/v1/users/githubcallback/createaccount",
            get(github_create),
        )
        .route("/api/v1/users/githubcallback/login", get(github_login))
        .route(
            "/api/v1/users/googlecallback/addmethod",
            get(google_add_method),
        )
        .route(
            "/api/v1/users/googlecallback/addpassword",
            get(google_add_password),
        )
        .route(
            "/api/v1/users/googlecallback/addpasswordfinal",
            post(google_add_password_final),
        )
        .route(
            "/api/v1/users/googlecallback/createaccount",
            get(google_create),
        )
        .route("/api/v1/users/googlecallback/login", get(google_login))
}

async fn login_oauth_account(Query(query): Query<StartQuery>) -> Response {
    start_flow(query, FlowKind::Login, None).await
}

async fn create_oauth_account(
    State(database): State<Database>,
    Query(query): Query<StartQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    match account_creation_enabled(pool).await {
        Ok(true) => start_flow(query, FlowKind::CreateAccount, None).await,
        Ok(false) => api_error(StatusCode::FORBIDDEN, "Account creation is not enabled"),
        Err(error) => query_failed(error),
    }
}

async fn add_oauth_method(
    State(database): State<Database>,
    Query(query): Query<StartQuery>,
) -> Response {
    start_authenticated_flow(database, query, FlowKind::AddMethod).await
}

async fn add_password(
    State(database): State<Database>,
    Query(query): Query<StartQuery>,
) -> Response {
    start_authenticated_flow(database, query, FlowKind::AddPassword).await
}

async fn start_authenticated_flow(
    database: Database,
    query: StartQuery,
    kind: FlowKind,
) -> Response {
    let Some(provider) = Provider::parse(query.method.clone()) else {
        return api_error(StatusCode::BAD_REQUEST, "Invalid method");
    };
    let token = query.token.unwrap_or_default();
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };
    if kind == FlowKind::AddMethod {
        match identity_for_user(pool, &user.id, provider).await {
            Ok(true) => return api_error(StatusCode::BAD_REQUEST, "Method already added"),
            Ok(false) => {}
            Err(error) => return query_failed(error),
        }
    }
    start_flow_for_provider(provider, kind, Some(user.id)).await
}

async fn start_flow(query: StartQuery, kind: FlowKind, user_id: Option<String>) -> Response {
    let Some(provider) = Provider::parse(query.method) else {
        return api_error(StatusCode::BAD_REQUEST, "Invalid method");
    };
    start_flow_for_provider(provider, kind, user_id).await
}

async fn start_flow_for_provider(
    provider: Provider,
    kind: FlowKind,
    user_id: Option<String>,
) -> Response {
    let state = random_token();
    let flow = OAuthFlow {
        provider,
        kind,
        user_id,
    };
    if let Err(response) = ephemeral_put("oauth:state", &state, &flow).await {
        return response;
    }
    let callback = callback_url(provider, kind);
    match authorization_url(provider, &callback, &state) {
        Ok(url) => Redirect::temporary(&url).into_response(),
        Err(response) => response,
    }
}

async fn scratch_add_method(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Scratch, FlowKind::AddMethod).await
}
async fn scratch_add_password(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Scratch, FlowKind::AddPassword).await
}
async fn scratch_create(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Scratch, FlowKind::CreateAccount).await
}
async fn scratch_login(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Scratch, FlowKind::Login).await
}
async fn github_add_method(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Github, FlowKind::AddMethod).await
}
async fn github_add_password(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Github, FlowKind::AddPassword).await
}
async fn github_create(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Github, FlowKind::CreateAccount).await
}
async fn github_login(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Github, FlowKind::Login).await
}
async fn google_add_method(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Google, FlowKind::AddMethod).await
}
async fn google_add_password(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Google, FlowKind::AddPassword).await
}
async fn google_create(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Google, FlowKind::CreateAccount).await
}
async fn google_login(state: State<Database>, query: Query<CallbackQuery>) -> Response {
    oauth_callback(state.0, query.0, Provider::Google, FlowKind::Login).await
}

async fn oauth_callback(
    database: Database,
    query: CallbackQuery,
    provider: Provider,
    expected_kind: FlowKind,
) -> Response {
    let Some(state) = query.state.filter(|value| !value.is_empty()) else {
        return api_error(StatusCode::BAD_REQUEST, "Missing state or code");
    };
    let Some(code) = query.code.filter(|value| !value.is_empty()) else {
        return api_error(StatusCode::BAD_REQUEST, "Missing state or code");
    };
    let flow: OAuthFlow = match ephemeral_take("oauth:state", &state).await {
        Ok(Some(flow)) => flow,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Invalid state"),
        Err(response) => return response,
    };
    if flow.provider != provider || flow.kind != expected_kind {
        return api_error(StatusCode::BAD_REQUEST, "Invalid state");
    }
    let callback = callback_url(provider, expected_kind);
    let profile = match provider_profile(provider, &code, &callback).await {
        Ok(profile) => profile,
        Err(response) => return response,
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    match expected_kind {
        FlowKind::Login => login_with_identity(pool, provider, profile).await,
        FlowKind::CreateAccount => create_with_identity(pool, provider, profile).await,
        FlowKind::AddMethod => {
            let Some(user_id) = flow.user_id else {
                return api_error(StatusCode::BAD_REQUEST, "Invalid state");
            };
            add_identity(pool, &user_id, provider, profile).await
        }
        FlowKind::AddPassword => {
            let Some(user_id) = flow.user_id else {
                return api_error(StatusCode::BAD_REQUEST, "Invalid state");
            };
            issue_password_ticket(pool, user_id, provider, profile).await
        }
    }
}

async fn login_with_identity(
    pool: &PgPool,
    provider: Provider,
    profile: ProviderProfile,
) -> Response {
    let user = sqlx::query_as::<_, (String, String)>(
        "SELECT u.id, u.username::text FROM app.oauth_identities oi
         JOIN app.users u ON u.id = oi.user_id
         WHERE oi.provider = $1 AND oi.provider_subject = $2
           AND NOT u.permanently_banned AND (u.unban_at IS NULL OR u.unban_at <= now())",
    )
    .bind(provider.as_str())
    .bind(profile.subject)
    .fetch_optional(pool)
    .await;
    let (user_id, username) = match user {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "MethodNotConnected"),
        Err(error) => return query_failed(error),
    };
    create_login_redirect(pool, &user_id, &username).await
}

async fn create_with_identity(
    pool: &PgPool,
    provider: Provider,
    profile: ProviderProfile,
) -> Response {
    match account_creation_enabled(pool).await {
        Ok(false) => return api_error(StatusCode::FORBIDDEN, "Account creation is not enabled"),
        Ok(true) => {}
        Err(error) => return query_failed(error),
    }
    match identity_owner(pool, provider, &profile.subject).await {
        Ok(Some(_)) => return api_error(StatusCode::BAD_REQUEST, "AccountExists"),
        Ok(None) => {}
        Err(error) => return query_failed(error),
    }
    let (username, display_username) =
        match available_username(pool, &profile.suggested_username).await {
            Ok(value) => value,
            Err(error) => return query_failed(error),
        };
    let user_id = ulid::Ulid::new().to_string();
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = sqlx::query(
        "INSERT INTO app.users (
            id, username, display_username, password_hash, first_login_at, last_login_at,
            email_verified, birthday_entered, country_entered, last_privacy_policy_read_at,
            last_terms_read_at, last_guidelines_read_at
         ) VALUES ($1, $2, $3, '', now(), now(), false, false, false, now(), now(), now())",
    )
    .bind(&user_id)
    .bind(&username)
    .bind(&display_username)
    .execute(&mut *transaction)
    .await
    {
        return query_failed(error);
    }
    if let Err(error) = sqlx::query("INSERT INTO app.user_private_details (user_id) VALUES ($1)")
        .bind(&user_id)
        .execute(&mut *transaction)
        .await
    {
        return query_failed(error);
    }
    if let Err(error) =
        insert_identity(&mut transaction, &user_id, provider, &profile.subject).await
    {
        return identity_insert_failed(error);
    }
    let token = match create_session_executor(&mut transaction, &user_id).await {
        Ok(token) => token,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = transaction.commit().await {
        return query_failed(error);
    }
    success_redirect(&token, &username)
}

async fn add_identity(
    pool: &PgPool,
    user_id: &str,
    provider: Provider,
    profile: ProviderProfile,
) -> Response {
    match identity_owner(pool, provider, &profile.subject).await {
        Ok(Some(owner)) if owner == user_id => {
            return api_error(StatusCode::BAD_REQUEST, "Method already added");
        }
        Ok(Some(_)) => return api_error(StatusCode::BAD_REQUEST, "Method already connected"),
        Ok(None) => {}
        Err(error) => return query_failed(error),
    }
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = insert_identity(&mut transaction, user_id, provider, &profile.subject).await
    {
        return identity_insert_failed(error);
    }
    let username =
        match sqlx::query_scalar::<_, String>("SELECT username::text FROM app.users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *transaction)
            .await
        {
            Ok(username) => username,
            Err(error) => return query_failed(error),
        };
    let token = match create_session_executor(&mut transaction, user_id).await {
        Ok(token) => token,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = transaction.commit().await {
        return query_failed(error);
    }
    success_redirect(&token, &username)
}

async fn issue_password_ticket(
    pool: &PgPool,
    user_id: String,
    provider: Provider,
    profile: ProviderProfile,
) -> Response {
    match identity_owner(pool, provider, &profile.subject).await {
        Ok(Some(owner)) if owner == user_id => {}
        Ok(_) => return api_error(StatusCode::BAD_REQUEST, "User not found"),
        Err(error) => return query_failed(error),
    }
    let ticket = random_token();
    let payload = PasswordTicket {
        user_id,
        provider,
        provider_subject: profile.subject,
    };
    if let Err(response) = ephemeral_put("oauth:password", &ticket, &payload).await {
        return response;
    }
    let mut url = match reqwest::Url::parse(HOME_URL) {
        Ok(url) => url,
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
    };
    url.set_path("/oauthchangepasswordintermediate");
    url.query_pairs_mut()
        .append_pair("method", provider.as_str())
        .append_pair("at", &ticket);
    Redirect::temporary(url.as_str()).into_response()
}

async fn github_add_password_final(
    State(database): State<Database>,
    Json(body): Json<PasswordBody>,
) -> Response {
    finish_add_password(
        database,
        legacy_json_string(body.at),
        legacy_json_string(body.password),
    )
    .await
}

async fn google_add_password_final(
    State(database): State<Database>,
    Json(body): Json<PasswordBody>,
) -> Response {
    finish_add_password(
        database,
        legacy_json_string(body.at),
        legacy_json_string(body.password),
    )
    .await
}

async fn scratch_add_password_final(
    State(database): State<Database>,
    Query(query): Query<ScratchPasswordQuery>,
) -> Response {
    finish_add_password(
        database,
        query.at.unwrap_or_default(),
        query.password.unwrap_or_default(),
    )
    .await
}

async fn finish_add_password(database: Database, ticket: String, password: String) -> Response {
    if ticket.is_empty() || password.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "Missing access_token or password");
    }
    if !(8..=50).contains(&password.chars().count()) {
        return api_error(StatusCode::BAD_REQUEST, "InvalidLengthPassword");
    }
    if !password_requirements(&password) {
        return api_error(StatusCode::BAD_REQUEST, "MissingRequirementsPassword");
    }
    let payload: PasswordTicket = match ephemeral_take("oauth:password", &ticket).await {
        Ok(Some(payload)) => payload,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Invalid access token"),
        Err(response) => return response,
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    match identity_owner(pool, payload.provider, &payload.provider_subject).await {
        Ok(Some(owner)) if owner == payload.user_id => {}
        Ok(_) => return api_error(StatusCode::BAD_REQUEST, "User not found"),
        Err(error) => return query_failed(error),
    }
    let password_hash = match hash_password(password).await {
        Ok(hash) => hash,
        Err(response) => return response,
    };
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    let username = match sqlx::query_scalar::<_, String>(
        "UPDATE app.users SET password_hash = $1, updated_at = now() WHERE id = $2
         RETURNING username::text",
    )
    .bind(password_hash)
    .bind(&payload.user_id)
    .fetch_one(&mut *transaction)
    .await
    {
        Ok(username) => username,
        Err(error) => return query_failed(error),
    };
    let token = match create_session_executor(&mut transaction, &payload.user_id).await {
        Ok(token) => token,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = transaction.commit().await {
        return query_failed(error);
    }
    Json(PasswordResponse { token, username }).into_response()
}

async fn remove_oauth_method(
    State(database): State<Database>,
    Json(body): Json<RemoveMethodBody>,
) -> Response {
    let method = legacy_json_string(body.method);
    let token = legacy_json_string(body.token);
    let Some(provider) = Provider::parse(Some(method)) else {
        return api_error(StatusCode::BAD_REQUEST, "Method not found");
    };
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    let user = match authenticate_token(pool, &token).await {
        Ok(Some(user)) => user,
        Ok(None) => return api_error(StatusCode::BAD_REQUEST, "Reauthenticate"),
        Err(error) => return query_failed(error),
    };
    let result =
        sqlx::query("DELETE FROM app.oauth_identities WHERE user_id = $1 AND provider = $2")
            .bind(user.id)
            .bind(provider.as_str())
            .execute(pool)
            .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => {
            Json(SuccessBody { success: true }).into_response()
        }
        Ok(_) => api_error(StatusCode::BAD_REQUEST, "Method not found"),
        Err(error) => query_failed(error),
    }
}

async fn send_login_success(Query(query): Query<SuccessQuery>) -> Response {
    if query.token.as_deref().unwrap_or_default().is_empty()
        || query.username.as_deref().unwrap_or_default().is_empty()
    {
        return api_error(StatusCode::BAD_REQUEST, "Missing token or username");
    }
    let html = r#"<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PatternYard - Logging In</title></head><body><p>Please wait...</p><script>const opener=window.opener||window.parent;if(!opener)throw new Error('No parent window');const p=new URLSearchParams(location.search);opener.postMessage({token:p.get('token'),username:p.get('username')},'https://patternyard.dev');window.close();</script></body></html>"#;
    let mut response = (StatusCode::OK, html).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors https://patternyard.dev"),
    );
    response
}

async fn create_login_redirect(pool: &PgPool, user_id: &str, username: &str) -> Response {
    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = sqlx::query("UPDATE app.users SET last_login_at = now() WHERE id = $1")
        .bind(user_id)
        .execute(&mut *transaction)
        .await
    {
        return query_failed(error);
    }
    let token = match create_session_executor(&mut transaction, user_id).await {
        Ok(token) => token,
        Err(error) => return query_failed(error),
    };
    if let Err(error) = transaction.commit().await {
        return query_failed(error);
    }
    success_redirect(&token, username)
}

fn success_redirect(token: &str, username: &str) -> Response {
    let mut url = reqwest::Url::parse(API_URL).expect("static API URL is valid");
    url.set_path("/api/v1/users/sendloginsuccess");
    url.query_pairs_mut()
        .append_pair("token", token)
        .append_pair("username", username);
    Redirect::temporary(url.as_str()).into_response()
}

async fn provider_profile(
    provider: Provider,
    code: &str,
    callback: &str,
) -> Result<ProviderProfile, Response> {
    let access_token = exchange_code(provider, code, callback).await?;
    let client = reqwest::Client::new();
    let response = match provider {
        Provider::Github => {
            client
                .get("https://api.github.com/user")
                .bearer_auth(&access_token)
                .header(header::USER_AGENT, "PatternYard-Services")
                .send()
                .await
        }
        Provider::Google => {
            client
                .get("https://openidconnect.googleapis.com/v1/userinfo")
                .bearer_auth(&access_token)
                .send()
                .await
        }
        Provider::Scratch => {
            client
                .get("https://oauth2.scratch-wiki.info/w/rest.php/soa2/v0/user")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", base64_encode(access_token.as_bytes())),
                )
                .send()
                .await
        }
    }
    .map_err(|error| {
        tracing::warn!(%error, provider = provider.as_str(), "OAuth profile request failed");
        api_error(StatusCode::BAD_GATEWAY, "OAuthServerDidNotRespond")
    })?;
    if !response.status().is_success() {
        tracing::warn!(status = %response.status(), provider = provider.as_str(), "OAuth profile request was rejected");
        return Err(api_error(StatusCode::BAD_GATEWAY, "OAuthServerError"));
    }
    let payload: Value = response.json().await.map_err(|error| {
        tracing::warn!(%error, provider = provider.as_str(), "OAuth profile response was invalid");
        api_error(StatusCode::BAD_GATEWAY, "OAuthServerError")
    })?;
    let (subject, username) = match provider {
        Provider::Github => (
            json_scalar(payload.get("id")),
            payload
                .get("login")
                .and_then(Value::as_str)
                .map(str::to_owned),
        ),
        Provider::Google => (
            json_scalar(payload.get("sub")),
            payload
                .get("given_name")
                .or_else(|| payload.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned),
        ),
        Provider::Scratch => (
            json_scalar(payload.get("user_id")),
            payload
                .get("user_name")
                .and_then(Value::as_str)
                .map(str::to_owned),
        ),
    };
    let Some(subject) = subject.filter(|value| !value.is_empty()) else {
        return Err(api_error(StatusCode::BAD_GATEWAY, "OAuthServerError"));
    };
    Ok(ProviderProfile {
        subject,
        suggested_username: username.unwrap_or_else(|| "PatternBuilder".to_owned()),
    })
}

async fn exchange_code(provider: Provider, code: &str, callback: &str) -> Result<String, Response> {
    let client = reqwest::Client::new();
    let response = match provider {
        Provider::Github => {
            let client_id = required_env(&["GITHUB_OAUTH_CLIENT_ID", "GithubOAuthClientID"])?;
            let client_secret =
                required_env(&["GITHUB_OAUTH_CLIENT_SECRET", "GithubOAuthClientSecret"])?;
            client
                .post("https://github.com/login/oauth/access_token")
                .header(header::ACCEPT, "application/json")
                .json(&json!({
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "redirect_uri": callback,
                }))
                .send()
                .await
        }
        Provider::Google => {
            let client_id = required_env(&["GOOGLE_OAUTH_CLIENT_ID", "GoogleOAuthClientID"])?;
            let client_secret =
                required_env(&["GOOGLE_OAUTH_CLIENT_SECRET", "GoogleOAuthClientSecret"])?;
            client
                .post("https://oauth2.googleapis.com/token")
                .form(&[
                    ("client_id", client_id.as_str()),
                    ("client_secret", client_secret.as_str()),
                    ("code", code),
                    ("grant_type", "authorization_code"),
                    ("redirect_uri", callback),
                ])
                .send()
                .await
        }
        Provider::Scratch => {
            let client_id = required_env(&["SCRATCH_OAUTH_CLIENT_ID", "ScratchOAuthClientID"])?;
            let client_secret =
                required_env(&["SCRATCH_OAUTH_CLIENT_SECRET", "ScratchOAuthClientSecret"])?;
            let numeric_id = client_id.parse::<u64>().map_err(|_| {
                tracing::error!("Scratch OAuth client ID is not numeric");
                oauth_unavailable()
            })?;
            client
                .post("https://oauth2.scratch-wiki.info/w/rest.php/soa2/v0/tokens")
                .json(&json!({
                    "client_id": numeric_id,
                    "client_secret": client_secret,
                    "code": code,
                    "scopes": ["identify"],
                }))
                .send()
                .await
        }
    }
    .map_err(|error| {
        tracing::warn!(%error, provider = provider.as_str(), "OAuth token exchange failed");
        api_error(StatusCode::BAD_GATEWAY, "OAuthServerDidNotRespond")
    })?;
    if !response.status().is_success() {
        tracing::warn!(status = %response.status(), provider = provider.as_str(), "OAuth token exchange was rejected");
        return Err(api_error(StatusCode::BAD_REQUEST, "Invalid code"));
    }
    let payload: Value = response.json().await.map_err(|error| {
        tracing::warn!(%error, provider = provider.as_str(), "OAuth token response was invalid");
        api_error(StatusCode::BAD_GATEWAY, "OAuthServerError")
    })?;
    payload
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "Invalid code"))
}

fn authorization_url(provider: Provider, callback: &str, state: &str) -> Result<String, Response> {
    let (base, client_id) = match provider {
        Provider::Scratch => (
            "https://oauth2.scratch-wiki.info/wiki/Special:ScratchOAuth2/authorize",
            required_env(&["SCRATCH_OAUTH_CLIENT_ID", "ScratchOAuthClientID"]),
        ),
        Provider::Github => (
            "https://github.com/login/oauth/authorize",
            required_env(&["GITHUB_OAUTH_CLIENT_ID", "GithubOAuthClientID"]),
        ),
        Provider::Google => (
            "https://accounts.google.com/o/oauth2/v2/auth",
            required_env(&["GOOGLE_OAUTH_CLIENT_ID", "GoogleOAuthClientID"]),
        ),
    };
    let client_id = client_id?;
    let mut url = reqwest::Url::parse(base).map_err(|_| oauth_unavailable())?;
    let mut query = url.query_pairs_mut();
    query
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", callback)
        .append_pair("state", state);
    match provider {
        Provider::Scratch => {
            query.append_pair("scopes", "identify");
        }
        Provider::Github => {
            query.append_pair("scope", "read:user");
        }
        Provider::Google => {
            query
                .append_pair("response_type", "code")
                .append_pair("scope", "openid profile")
                .append_pair("access_type", "offline");
        }
    }
    drop(query);
    Ok(url.to_string())
}

fn callback_url(provider: Provider, kind: FlowKind) -> String {
    let path = match (provider, kind) {
        (Provider::Scratch, FlowKind::Login) => "/api/v1/users/scratchoauthlogin",
        (Provider::Scratch, FlowKind::CreateAccount) => "/api/v1/users/scratchoauthcreate",
        (Provider::Scratch, FlowKind::AddMethod) => "/api/v1/users/addscratchlogin",
        (Provider::Scratch, FlowKind::AddPassword) => "/api/v1/users/scratchaddpassword",
        (Provider::Github, FlowKind::Login) => "/api/v1/users/githubcallback/login",
        (Provider::Github, FlowKind::CreateAccount) => "/api/v1/users/githubcallback/createaccount",
        (Provider::Github, FlowKind::AddMethod) => "/api/v1/users/githubcallback/addmethod",
        (Provider::Github, FlowKind::AddPassword) => "/api/v1/users/githubcallback/addpassword",
        (Provider::Google, FlowKind::Login) => "/api/v1/users/googlecallback/login",
        (Provider::Google, FlowKind::CreateAccount) => "/api/v1/users/googlecallback/createaccount",
        (Provider::Google, FlowKind::AddMethod) => "/api/v1/users/googlecallback/addmethod",
        (Provider::Google, FlowKind::AddPassword) => "/api/v1/users/googlecallback/addpassword",
    };
    format!("{API_URL}{path}")
}

async fn insert_identity(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: &str,
    provider: Provider,
    subject: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO app.oauth_identities (provider, provider_subject, user_id)
         VALUES ($1, $2, $3)",
    )
    .bind(provider.as_str())
    .bind(subject)
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn identity_owner(
    pool: &PgPool,
    provider: Provider,
    subject: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT user_id FROM app.oauth_identities WHERE provider = $1 AND provider_subject = $2",
    )
    .bind(provider.as_str())
    .bind(subject)
    .fetch_optional(pool)
    .await
}

async fn identity_for_user(
    pool: &PgPool,
    user_id: &str,
    provider: Provider,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM app.oauth_identities WHERE user_id = $1 AND provider = $2)",
    )
    .bind(user_id)
    .bind(provider.as_str())
    .fetch_one(pool)
    .await
}

async fn available_username(
    pool: &PgPool,
    suggestion: &str,
) -> Result<(String, String), sqlx::Error> {
    let mut base: String = suggestion
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || *character == '_' || *character == '-'
        })
        .take(20)
        .collect();
    if base.len() < 3 {
        base = "PatternBuilder".to_owned();
    }
    for suffix in 0..10_000_u16 {
        let suffix = if suffix == 0 {
            String::new()
        } else {
            suffix.to_string()
        };
        let keep = 20_usize.saturating_sub(suffix.len());
        let stem: String = base.chars().take(keep).collect();
        let display = format!("{stem}{suffix}");
        let username = display.to_lowercase();
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM app.users WHERE username = $1)")
                .bind(&username)
                .fetch_one(pool)
                .await?;
        if !exists {
            return Ok((username, display));
        }
    }
    Ok((
        format!("builder{}", ulid::Ulid::new()),
        "PatternBuilder".to_owned(),
    ))
}

async fn account_creation_enabled(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let value = sqlx::query_scalar::<_, Value>(
        "SELECT value FROM app.runtime_config WHERE key = 'accountCreationEnabled'",
    )
    .fetch_optional(pool)
    .await?;
    Ok(value.and_then(|value| value.as_bool()).unwrap_or(true))
}

async fn ephemeral_put<T: Serialize>(prefix: &str, key: &str, value: &T) -> Result<(), Response> {
    let value = serde_json::to_string(value).map_err(|error| {
        tracing::error!(%error, "failed to serialize OAuth state");
        oauth_unavailable()
    })?;
    let result = redis_command(json!([
        "SET",
        format!("{prefix}:{key}"),
        value,
        "EX",
        FLOW_TTL_SECONDS,
        "NX"
    ]))
    .await?;
    if result.get("result") == Some(&Value::String("OK".to_owned())) {
        Ok(())
    } else {
        tracing::error!(?result, "Upstash rejected OAuth state write");
        Err(oauth_unavailable())
    }
}

async fn ephemeral_take<T: for<'de> Deserialize<'de>>(
    prefix: &str,
    key: &str,
) -> Result<Option<T>, Response> {
    let result = redis_command(json!(["GETDEL", format!("{prefix}:{key}")])).await?;
    let Some(value) = result.get("result") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(value) = value.as_str() else {
        return Ok(None);
    };
    serde_json::from_str(value).map(Some).map_err(|error| {
        tracing::error!(%error, "stored OAuth state was invalid");
        api_error(StatusCode::BAD_REQUEST, "Invalid state")
    })
}

async fn redis_command(command: Value) -> Result<Value, Response> {
    let url = required_env(&["KV_REST_API_URL", "UPSTASH_REDIS_REST_URL"])?;
    let token = required_env(&["KV_REST_API_TOKEN", "UPSTASH_REDIS_REST_TOKEN"])?;
    let response = reqwest::Client::new()
        .post(url)
        .bearer_auth(token)
        .json(&command)
        .send()
        .await
        .map_err(|error| {
            tracing::error!(%error, "OAuth state store request failed");
            oauth_unavailable()
        })?;
    if !response.status().is_success() {
        tracing::error!(status = %response.status(), "OAuth state store rejected request");
        return Err(oauth_unavailable());
    }
    response.json().await.map_err(|error| {
        tracing::error!(%error, "OAuth state store response was invalid");
        oauth_unavailable()
    })
}

fn required_env(names: &[&str]) -> Result<String, Response> {
    for name in names {
        if let Ok(value) = env::var(name)
            && !value.is_empty()
        {
            return Ok(value);
        }
    }
    tracing::error!(variables = ?names, "OAuth configuration is missing");
    Err(oauth_unavailable())
}

fn oauth_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "OAuthUnavailable")
}

fn identity_insert_failed(error: sqlx::Error) -> Response {
    if error
        .as_database_error()
        .and_then(|error| error.constraint())
        .is_some()
    {
        return api_error(StatusCode::BAD_REQUEST, "Method already connected");
    }
    query_failed(error)
}

fn json_scalar(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn legacy_json_string(value: Option<Value>) -> String {
    match value {
        Some(Value::String(value)) => value,
        Some(value) if !value.is_null() => value.to_string(),
        _ => "undefined".to_owned(),
    }
}

fn password_requirements(password: &str) -> bool {
    password.chars().any(|value| value.is_ascii_lowercase())
        && password.chars().any(|value| value.is_ascii_uppercase())
        && password.chars().any(|value| value.is_ascii_digit())
        && password.chars().any(|value| !value.is_ascii_alphanumeric())
}

fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(TABLE[(a >> 2) as usize] as char);
        output.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(c & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "DatabaseUnavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "OAuth database query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_routes_are_patternyard_only() {
        for provider in [Provider::Scratch, Provider::Github, Provider::Google] {
            for kind in [
                FlowKind::Login,
                FlowKind::CreateAccount,
                FlowKind::AddMethod,
                FlowKind::AddPassword,
            ] {
                assert!(callback_url(provider, kind).starts_with(API_URL));
            }
        }
    }

    #[test]
    fn base64_matches_scratch_legacy_header_encoding() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn password_requirements_match_legacy_contract() {
        assert!(password_requirements("Builder1!"));
        assert!(!password_requirements("builder1!"));
        assert!(!password_requirements("Builder!!"));
    }

    #[test]
    fn provider_parser_is_strict() {
        assert_eq!(
            Provider::parse(Some("github".into())),
            Some(Provider::Github)
        );
        assert_eq!(Provider::parse(Some("GitHub".into())), None);
        assert_eq!(Provider::parse(None), None);
    }
}
