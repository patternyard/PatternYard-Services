use axum::Json;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    path: String,
}

pub async fn not_found(uri: Uri) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: "Not found",
            path: uri.path().to_owned(),
        }),
    )
        .into_response()
}
