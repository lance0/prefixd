use axum::{body::Body, http::Request, middleware::Next, response::Response};
use uuid::Uuid;

const REQUEST_ID_HEADER: &str = "x-request-id";

/// Middleware that assigns a correlation ID to each request.
/// If the client sends `x-request-id`, it is preserved; otherwise a UUID is generated.
/// The ID is added to the tracing span and echoed back in the response header.
const MAX_REQUEST_ID_LEN: usize = 128;

pub async fn request_id(mut req: Request<Body>, next: Next) -> Response {
    let id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.len() <= MAX_REQUEST_ID_LEN && s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.'))
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    if let Ok(val) = id.parse() {
        req.headers_mut().insert(REQUEST_ID_HEADER, val);
    }

    let span = tracing::info_span!("request", request_id = %id);
    let _guard = span.enter();

    let mut response = next.run(req).await;

    if let Ok(val) = id.parse() {
        response.headers_mut().insert(REQUEST_ID_HEADER, val);
    }

    response
}
