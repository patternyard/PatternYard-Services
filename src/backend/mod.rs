use axum::Json;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;

const SERVICE_NAME: &str = "PatternYard Services";
const API_VERSION: &str = "0.1.0";

#[derive(Serialize)]
struct ApiMetadata<'a> {
    name: &'a str,
    version: VersionMetadata<'a>,
    status: &'a str,
}

#[derive(Serialize)]
struct VersionMetadata<'a> {
    api: &'a str,
    git: &'a str,
}

pub fn router() -> Router {
    Router::new()
        .route("/", get(home))
        .route("/api/v1", get(metadata))
        .route("/api/v1/", get(metadata))
        .route("/api/v1/ping", get(ping))
        .route("/api/v1/robots.txt", get(robots))
        .route("/robots.txt", get(robots))
}

async fn home() -> &'static str {
    "PatternYard Services"
}

async fn ping() -> &'static str {
    "Pong!"
}

async fn metadata() -> Json<ApiMetadata<'static>> {
    Json(ApiMetadata {
        name: SERVICE_NAME,
        version: VersionMetadata {
            api: API_VERSION,
            git: option_env!("VERCEL_GIT_COMMIT_SHA").unwrap_or("Unknown"),
        },
        status: "foundation",
    })
}

async fn robots() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "User-agent: *\nDisallow: /\n",
    )
        .into_response()
}
