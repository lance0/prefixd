use axum::{body::Body, http::Request, middleware::Next, response::Response};
use uuid::Uuid;

const REQUEST_ID_HEADER: &str = "x-request-id";

/// Middleware that assigns a correlation ID to each request.
/// If the client sends `x-request-id`, it is preserved; otherwise a UUID is generated.
/// The ID is added to the tracing span and echoed back in the response header.
pub async fn request_id(mut req: Request<Body>, next: Next) -> Response {
    let id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    req.headers_mut().insert(
        REQUEST_ID_HEADER,
        id.parse().expect("valid header value"),
    );

    let span = tracing::info_span!("request", request_id = %id);
    let _guard = span.enter();

    let mut response = next.run(req).await;

    response.headers_mut().insert(
        REQUEST_ID_HEADER,
        id.parse().expect("valid header value"),
    );

    response
}
