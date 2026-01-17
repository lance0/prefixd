//! HTTP metrics middleware for Prometheus

use axum::{body::Body, extract::MatchedPath, http::Request, middleware::Next, response::Response};
use std::time::Instant;

use crate::observability::metrics::{HTTP_IN_FLIGHT, HTTP_REQUESTS_TOTAL, HTTP_REQUEST_DURATION};

/// Middleware to collect HTTP metrics (requests, duration, in-flight)
pub async fn http_metrics(req: Request<Body>, next: Next) -> Response {
    let method = req.method().to_string();

    // Get route from extensions (set by axum's router)
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());

    // Skip /metrics to avoid self-scrape noise
    if route == "/metrics" {
        return next.run(req).await;
    }

    HTTP_IN_FLIGHT.with_label_values(&[&method, &route]).inc();
    let start = Instant::now();

    let response = next.run(req).await;

    let status_class = match response.status().as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    };

    let status_class = status_class.to_string();
    HTTP_IN_FLIGHT.with_label_values(&[&method, &route]).dec();
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[&method, &route, &status_class])
        .inc();
    HTTP_REQUEST_DURATION
        .with_label_values(&[&method, &route, &status_class])
        .observe(start.elapsed().as_secs_f64());

    response
}
