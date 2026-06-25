use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Service {
    Api,
    Storage,
    Captcha,
    Preview,
}

impl Service {
    fn from_host(host: &str) -> Self {
        let host = host.split(':').next().unwrap_or(host);
        match host {
            "api.patternyard.dev" => Self::Api,
            "storage.patternyard.dev" => Self::Storage,
            "captcha.patternyard.dev" => Self::Captcha,
            _ => Self::Preview,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Storage => "storage",
            Self::Captcha => "captcha",
            Self::Preview => "preview",
        }
    }
}

pub async fn identify_service(mut request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let service = Service::from_host(host);
    request.extensions_mut().insert(service);

    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "x-patternyard-service",
        HeaderValue::from_static(service.as_str()),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_production_hosts_without_affecting_previews() {
        assert_eq!(Service::from_host("api.patternyard.dev"), Service::Api);
        assert_eq!(
            Service::from_host("storage.patternyard.dev"),
            Service::Storage
        );
        assert_eq!(
            Service::from_host("captcha.patternyard.dev"),
            Service::Captcha
        );
        assert_eq!(Service::from_host("localhost:3000"), Service::Preview);
    }
}
