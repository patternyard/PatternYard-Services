pub mod auth;
pub mod backend;
pub mod db;
pub mod error;
pub mod host;
pub mod observability;

use axum::Router;
use axum::http::{HeaderName, Method, header};
use axum::middleware;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;

pub fn app() -> Router {
    app_with_router(backend::router())
}

fn app_with_router(router: Router) -> Router {
    let request_id = HeaderName::from_static("x-request-id");
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ]);

    router
        .fallback(error::not_found)
        .layer(middleware::from_fn(host::identify_service))
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .layer(SetSensitiveRequestHeadersLayer::new(std::iter::once(
            header::AUTHORIZATION,
        )))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn ping_preserves_the_legacy_contract() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/ping")
                    .header("host", "api.patternyard.dev")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "Pong!"
        );
    }

    #[tokio::test]
    async fn home_redirects_to_patternyard() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "api.patternyard.dev")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://patternyard.dev"
        );
    }

    #[tokio::test]
    async fn readiness_is_explicit_without_database_configuration() {
        let router = backend::router_with_database(db::Database::default());
        let response = app_with_router(router)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/ready")
                    .header("host", "api.patternyard.dev")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn account_creation_route_is_mounted() {
        let router = backend::router_with_database(db::Database::default());
        let response = app_with_router(router)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/users/createAccount")
                    .header("host", "api.patternyard.dev")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn unknown_routes_return_a_stable_json_error() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/not-implemented")
                    .header("host", "api.patternyard.dev")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    }
}
