use axum::{
    Json,
    extract::{ConnectInfo, MatchedPath, Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::config::RateLimitConfig;
use crate::observability::metrics::HTTP_RATE_LIMITED;

/// Request class with its own token buckets. Withdrawals are operator
/// mutations, so a detector flood never drains their bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitClass {
    /// Detector events: `POST /v1/events` and `/v1/events/batch`.
    Ingest,
    /// Detector and corroborator adapters: `POST /v1/signals/*`.
    Signals,
    /// Every other matched `POST`, `PUT` and `DELETE`, including withdrawals.
    Mutation,
    /// `GET` and other safe methods on matched routes.
    Read,
    /// `POST /v1/auth/login` and unmatched routes of any method, so a login
    /// storm or junk requests through a shared proxy never reach `mutation`.
    Auth,
}

impl RateLimitClass {
    pub const ALL: [Self; 5] = [
        Self::Ingest,
        Self::Signals,
        Self::Mutation,
        Self::Read,
        Self::Auth,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::Signals => "signals",
            Self::Mutation => "mutation",
            Self::Read => "read",
            Self::Auth => "auth",
        }
    }

    /// `None` for exempt probes and the metrics scrape.
    fn of(method: &Method, route: Option<&str>) -> Option<Self> {
        let route = match route {
            Some("/v1/health" | "/v1/ready" | "/metrics") => return None,
            None | Some("/v1/auth/login") => return Some(Self::Auth),
            Some(route) => route,
        };
        if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
            return Some(Self::Read);
        }
        Some(match route {
            r if r == "/v1/events" || r.starts_with("/v1/events/") => Self::Ingest,
            r if r.starts_with("/v1/signals/") => Self::Signals,
            _ => Self::Mutation,
        })
    }
}

/// Bucket key for a peer. IPv6 peers share one bucket per /64 so rotating
/// addresses within a prefix neither escapes the limit nor grows the table.
fn client_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0u128 << 64))),
        v4 => v4,
    }
}

/// Token buckets per (class, client). Each bucket holds `burst` tokens and
/// refills at `events_per_second`. Requests without connection info (in-process
/// tests) share a single client per class.
pub struct RateLimiter {
    rate: f64,
    burst: f64,
    /// Time for an empty bucket to refill; idle buckets older than this are full.
    refill: Duration,
    state: Mutex<Buckets>,
}

struct Buckets {
    map: HashMap<(RateLimitClass, Option<IpAddr>), Bucket>,
    last_prune: Instant,
}

struct Bucket {
    tokens: f64,
    last_update: Instant,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Arc<Self> {
        let rate = config.events_per_second.max(1) as f64;
        let burst = config.burst as f64;
        Arc::new(Self {
            rate,
            burst,
            refill: Duration::from_secs_f64(burst / rate),
            state: Mutex::new(Buckets {
                map: HashMap::new(),
                last_prune: Instant::now(),
            }),
        })
    }

    pub fn check(&self, class: RateLimitClass, client: Option<IpAddr>) -> Result<(), Duration> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();

        // A bucket idle for a full refill is indistinguishable from a new one,
        // so dropping it bounds the table by recently active clients.
        if now.duration_since(state.last_prune) >= self.refill {
            let refill = self.refill;
            state
                .map
                .retain(|_, b| now.duration_since(b.last_update) < refill);
            // retain keeps the allocation; release it after a surge of clients.
            let keep = (state.map.len() * 2).max(64);
            state.map.shrink_to(keep);
            state.last_prune = now;
        }

        let bucket = state.map.entry((class, client)).or_insert(Bucket {
            tokens: self.burst,
            last_update: now,
        });
        let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.last_update = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - bucket.tokens) / self.rate))
        }
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    let Some(class) = RateLimitClass::of(request.method(), route) else {
        return next.run(request).await;
    };
    let client = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| client_key(addr.ip()));

    match limiter.check(class, client) {
        Ok(()) => next.run(request).await,
        Err(wait_time) => {
            let retry_after = wait_time.as_secs_f64().ceil().max(1.0) as u32;
            HTTP_RATE_LIMITED.with_label_values(&[class.as_str()]).inc();
            tracing::warn!(
                class = class.as_str(),
                client = ?client,
                retry_after_seconds = retry_after,
                "rate limit exceeded"
            );

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
    use RateLimitClass::*;

    fn limiter(events_per_second: u32, burst: u32) -> Arc<RateLimiter> {
        RateLimiter::new(RateLimitConfig {
            events_per_second,
            burst,
        })
    }

    #[test]
    fn test_rate_limiter_allows_burst() {
        let limiter = limiter(10, 5);
        for _ in 0..5 {
            assert!(limiter.check(Ingest, None).is_ok());
        }
        assert!(limiter.check(Ingest, None).is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_replenishes() {
        let limiter = limiter(100, 1);
        assert!(limiter.check(Ingest, None).is_ok());
        assert!(limiter.check(Ingest, None).is_err());
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(limiter.check(Ingest, None).is_ok());
    }

    #[test]
    fn exhausted_ingest_leaves_other_classes_and_clients_alone() {
        let limiter = limiter(1, 2);
        let detector = Some("192.0.2.1".parse().unwrap());
        let other = Some("192.0.2.2".parse().unwrap());
        while limiter.check(Ingest, detector).is_ok() {}
        assert!(limiter.check(Ingest, detector).is_err());
        for class in [Signals, Mutation, Read, Auth] {
            assert!(limiter.check(class, detector).is_ok(), "{class:?}");
        }
        assert!(limiter.check(Ingest, other).is_ok());
    }

    #[test]
    fn classifies_routes() {
        let cases = [
            (Method::GET, Some("/v1/health"), None),
            (Method::GET, Some("/v1/ready"), None),
            (Method::GET, Some("/metrics"), None),
            (Method::POST, Some("/v1/events"), Some(Ingest)),
            (Method::POST, Some("/v1/events/batch"), Some(Ingest)),
            (Method::GET, Some("/v1/events"), Some(Read)),
            (Method::POST, Some("/v1/signals/fastnetmon"), Some(Signals)),
            (
                Method::POST,
                Some("/v1/signals/webhook/{name}"),
                Some(Signals),
            ),
            (
                Method::GET,
                Some("/v1/signals/corroborator/cache"),
                Some(Read),
            ),
            (
                Method::POST,
                Some("/v1/mitigations/{id}/withdraw"),
                Some(Mutation),
            ),
            (
                Method::POST,
                Some("/v1/mitigations/withdraw"),
                Some(Mutation),
            ),
            (
                Method::POST,
                Some("/v1/diversions/{id}/withdraw"),
                Some(Mutation),
            ),
            (Method::POST, Some("/v1/auth/login"), Some(Auth)),
            (
                Method::DELETE,
                Some("/v1/safelist/{*prefix}"),
                Some(Mutation),
            ),
            (Method::GET, Some("/v1/health/detail"), Some(Read)),
            (Method::POST, Some("/v1/auth/logout"), Some(Mutation)),
            (Method::POST, None, Some(Auth)),
            (Method::GET, None, Some(Auth)),
            (Method::DELETE, None, Some(Auth)),
        ];
        for (method, route, class) in cases {
            assert_eq!(
                RateLimitClass::of(&method, route),
                class,
                "{method} {route:?}"
            );
        }
    }

    #[test]
    fn ipv6_clients_share_a_slash_64() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(client_key(a), client_key(b));
        assert_ne!(client_key(a), client_key(c));
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(client_key(mapped), "192.0.2.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn idle_full_buckets_are_pruned() {
        let limiter = limiter(1000, 1);
        for i in 0..50u8 {
            let _ = limiter.check(Ingest, Some(IpAddr::from([192, 0, 2, i])));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        let _ = limiter.check(Read, None);
        assert_eq!(limiter.state.lock().unwrap().map.len(), 1);
    }
}
