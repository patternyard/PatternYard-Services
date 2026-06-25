use patternyard_services::{app, observability};
use tower::ServiceBuilder;
use vercel_runtime::Error;
use vercel_runtime::axum::VercelLayer;

#[tokio::main]
async fn main() -> Result<(), Error> {
    observability::init();

    let service = ServiceBuilder::new()
        .layer(VercelLayer::new())
        .service(app());

    vercel_runtime::run(service).await
}
