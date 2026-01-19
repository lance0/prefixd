use axum::{
    Json,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::config::RateLimitConfig;

/// Simple token bucket rate limiter
pub struct RateLimiter {
    config: RateLimitConfig,
    state: Mutex<RateLimiterState>,
}

struct RateLimiterState {
    tokens: f64,
    last_update: Instant,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(RateLimiterState {
                tokens: config.burst as f64,
                last_update: Instant::now(),
            }),
            config,
        })
    }

    pub async fn check(&self) -> Result<(), Duration> {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_update);

        // Replenish tokens based on elapsed time
        let replenished = elapsed.as_secs_f64() * self.config.events_per_second as f64;
        state.tokens = (state.tokens + replenished).min(self.config.burst as f64);
        state.last_update = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate how long until a token is available
            let wait_time = Duration::from_secs_f64(
                (1.0 - state.tokens) / self.config.events_per_second as f64,
            );
            Err(wait_time)
        }
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    limiter: Arc<RateLimiter>,
    request: Request,
    next: Next,
) -> Response {
    match limiter.check().await {
        Ok(()) => next.run(request).await,
        Err(wait_time) => {
            let retry_after = wait_time.as_secs().max(1) as u32;
            tracing::warn!(retry_after_seconds = retry_after, "rate limit exceeded");

            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "rate_limited",
                    "retry_after_seconds": retry_after
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_burst() {
        let limiter = RateLimiter::new(RateLimitConfig {
            events_per_second: 10,
            burst: 5,
        });

        // Should allow burst of 5
        for _ in 0..5 {
            assert!(limiter.check().await.is_ok());
        }

        // 6th request should fail
        assert!(limiter.check().await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_replenishes() {
        let limiter = RateLimiter::new(RateLimitConfig {
            events_per_second: 100,
            burst: 1,
        });

        assert!(limiter.check().await.is_ok());
        assert!(limiter.check().await.is_err());

        // Wait for replenishment
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(limiter.check().await.is_ok());
    }
}
