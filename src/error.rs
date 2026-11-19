use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub scope: Option<&'static str>,
    pub retry_after: Option<u64>,
}

impl ApiError {
    pub fn new(status: u16, code: &'static str) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap(),
            code,
            scope: None,
            retry_after: None,
        }
    }
    pub fn bad_request() -> Self {
        Self::new(400, "bad_request")
    }
    pub fn bad_signature() -> Self {
        Self::new(401, "bad_signature")
    }
    pub fn blocked() -> Self {
        Self::new(403, "blocked")
    }
    pub fn too_large() -> Self {
        Self::new(413, "payload_too_large")
    }
    pub fn limited(scope: &'static str, retry_after: u64) -> Self {
        Self {
            scope: Some(scope),
            retry_after: Some(retry_after),
            ..Self::new(429, "rate_limited")
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!("database: {e}");
        Self::new(500, "internal")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.code });
        if let Some(scope) = self.scope {
            body["scope"] = scope.into();
        }
        let mut res = (self.status, Json(body)).into_response();
        if let Some(s) = self.retry_after {
            res.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(s));
        }
        res
    }
}
