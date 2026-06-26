use crate::db::Database;
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use serde::Serialize;

mod account_creation;
mod account_reads;
mod email_auth;
mod frontpage_projects;
mod message_mutations;
mod message_reads;
mod moderation_lists;
mod owned_project_reads;
mod policy_state;
mod profile_images;
mod profile_writes;
mod project_assets;
mod project_interactions;
mod project_moderation;
mod project_writes;
mod public_discovery;
mod public_projects;
mod public_state;
mod public_users;
mod report_mutations;
mod report_reads;
mod session_writes;
mod social_users;
mod staff_directory;
mod user_feed;

#[derive(Serialize)]
struct ApiMetadata<'a> {
    unavailable: Availability,
    testing: Availability,
    documentation: Documentation<'a>,
    version: VersionMetadata<'a>,
    detail: Detail,
}

#[derive(Serialize)]
struct Availability {
    main: bool,
}

#[derive(Serialize)]
struct Documentation<'a> {
    available: bool,
    url: &'a str,
}

#[derive(Serialize)]
struct VersionMetadata<'a> {
    host: &'a str,
    string: &'a str,
    number: u8,
    start: &'a str,
    agent: AgentMetadata<'a>,
    git: &'a str,
}

#[derive(Serialize)]
struct AgentMetadata<'a> {
    name: &'a str,
}

#[derive(Serialize)]
struct Detail {}

#[derive(Serialize)]
struct Readiness {
    service: &'static str,
    database: &'static str,
}

pub fn router() -> Router {
    router_with_database(Database::from_env())
}

pub(crate) fn router_with_database(database: Database) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/api/v1", get(metadata))
        .route("/api/v1/", get(metadata))
        .route("/api/v1/ping", get(ping))
        .route("/api/v1/ready", get(ready))
        .route("/api/v1/robots.txt", get(robots))
        .route("/robots.txt", get(robots))
        .merge(account_creation::router())
        .merge(account_reads::router())
        .merge(email_auth::router())
        .merge(frontpage_projects::router())
        .merge(message_mutations::router())
        .merge(message_reads::router())
        .merge(moderation_lists::router())
        .merge(owned_project_reads::router())
        .merge(policy_state::router())
        .merge(profile_images::router())
        .merge(profile_writes::router())
        .merge(project_assets::router())
        .merge(project_interactions::router())
        .merge(project_moderation::router())
        .merge(project_writes::router())
        .merge(public_discovery::router())
        .merge(public_projects::router())
        .merge(public_state::router())
        .merge(public_users::router())
        .merge(report_mutations::router())
        .merge(report_reads::router())
        .merge(session_writes::router())
        .merge(social_users::router())
        .merge(staff_directory::router())
        .merge(user_feed::router())
        .with_state(database)
}

async fn home() -> Redirect {
    Redirect::temporary("https://patternyard.dev")
}

async fn ping() -> &'static str {
    "Pong!"
}

async fn metadata() -> Json<ApiMetadata<'static>> {
    Json(ApiMetadata {
        unavailable: Availability { main: false },
        testing: Availability { main: false },
        documentation: Documentation {
            available: false,
            url: "",
        },
        version: VersionMetadata {
            host: "server",
            string: "v1.0.0-stable",
            number: 1,
            start: "v1.0.0",
            agent: AgentMetadata { name: "Server-1" },
            git: option_env!("VERCEL_GIT_COMMIT_SHA").unwrap_or("Unknown"),
        },
        detail: Detail {},
    })
}

async fn ready(State(database): State<Database>) -> impl IntoResponse {
    let is_ready = database.is_ready().await;
    let status = if is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(Readiness {
            service: "ready",
            database: if is_ready { "ready" } else { "unavailable" },
        }),
    )
}

async fn robots() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "User-agent: *\nDisallow: /\n",
    )
        .into_response()
}
