//! Named, hashed, revocable API tokens (ADR 034).
//!
//! One generator serves the admin API and `prefixdctl`. A token is `prefixd_`
//! followed by 43 base64url characters that encode 32 bytes from the operating
//! system's CSPRNG; rows store only its SHA-256. With 256 bits of randomness a
//! stolen hash gives no practical preimage, so no salt or slow KDF is used, and
//! the indexed lookup by hash needs no constant-time comparison.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::RepositoryTrait;
use crate::domain::{ApiToken, TokenScope, is_valid_token_name, is_valid_token_source};
use crate::error::{PrefixdError, Result};
use crate::observability::{ActorType, AuditEntry};

/// The fixed prefix that lets secret scanners recognize a leaked token.
pub const TOKEN_PREFIX: &str = "prefixd_";
const SECRET_BYTES: usize = 32;
const ENCODED_LEN: usize = 43;

/// The SHA-256 of a full token, which is what the database stores.
pub type TokenHash = [u8; 32];

/// The latest expiry a token may have, from its creation: about 100 years.
/// It keeps every expiry far inside the timestamp range.
pub fn max_lifetime() -> TimeDelta {
    TimeDelta::days(36_525)
}

/// The active controller writes `last_used_at` at most this often per token.
pub fn last_used_interval() -> TimeDelta {
    TimeDelta::seconds(60)
}

/// A new token and its hash. The plaintext goes to the creator once and is
/// never stored or logged.
pub fn generate() -> Result<(String, TokenHash)> {
    let mut secret = [0u8; SECRET_BYTES];
    getrandom::fill(&mut secret)
        .map_err(|error| PrefixdError::Internal(format!("OS random source failed: {error}")))?;
    let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(secret));
    let hash = hash(&token);
    Ok((token, hash))
}

pub fn hash(token: &str) -> TokenHash {
    Sha256::digest(token.as_bytes()).into()
}

/// The hash of a presented value that has the token format, or `None`. A value
/// that does not match is refused before any database query.
pub fn parse(presented: &[u8]) -> Option<TokenHash> {
    let encoded = presented.strip_prefix(TOKEN_PREFIX.as_bytes())?;
    if encoded.len() != ENCODED_LEN {
        return None;
    }
    // The default engine refuses noncanonical trailing bits, so each secret
    // has exactly one accepted spelling.
    let secret = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    (secret.len() == SECRET_BYTES).then(|| Sha256::digest(presented).into())
}

/// A token creation request, from the admin API or `prefixdctl tokens create`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewToken {
    /// `^[a-z0-9][a-z0-9-]{0,57}$`, unique across every token ever created
    pub name: String,
    pub scope: TokenScope,
    /// Required for `ingest`, refused otherwise: `^[a-z0-9][a-z0-9_-]{0,63}$`
    #[serde(default)]
    pub source: Option<String>,
    /// Bind the token to the controllers whose `pop` matches; omit for every
    /// POP that shares the database
    #[serde(default)]
    pub pop: Option<String>,
    /// Optional expiry, in the future; tokens do not expire by default
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

fn valid_pop(pop: &str) -> bool {
    (1..=64).contains(&pop.len()) && pop.bytes().all(|c| c.is_ascii_graphic())
}

fn audit(actor: &str, action: &str, token: &ApiToken) -> AuditEntry {
    AuditEntry::new(
        ActorType::Operator,
        Some(actor.to_owned()),
        action,
        Some("api_token"),
        Some(token.name.clone()),
        serde_json::json!({
            "scope": token.scope,
            "source": token.source,
            "pop": token.pop,
            "expires_at": token.expires_at,
        }),
    )
}

/// Validate and store a new token with its `api_token.create` audit row, and
/// return the record with the plaintext. `actor` is the Admin session's
/// username or `prefixdctl`.
pub async fn create(
    repo: &dyn RepositoryTrait,
    request: NewToken,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<(ApiToken, String)> {
    let invalid = |message: &str| Err(PrefixdError::InvalidRequest(message.into()));
    if !is_valid_token_name(&request.name) {
        return invalid("name must match ^[a-z0-9][a-z0-9-]{0,57}$");
    }
    match (request.scope, &request.source) {
        (TokenScope::Ingest, None) => return invalid("an ingest token requires a source"),
        (TokenScope::Ingest, Some(source)) if !is_valid_token_source(source) => {
            return invalid("source must match ^[a-z0-9][a-z0-9_-]{0,63}$");
        }
        (TokenScope::Operator | TokenScope::Admin, Some(_)) => {
            return invalid("only an ingest token has a source");
        }
        _ => {}
    }
    if request.pop.as_deref().is_some_and(|pop| !valid_pop(pop)) {
        return invalid("pop must be 1 to 64 printable characters without spaces");
    }
    if request.expires_at.is_some_and(|expires| expires <= now) {
        return invalid("expires_at must be in the future");
    }
    let latest = now
        .checked_add_signed(max_lifetime())
        .ok_or_else(|| PrefixdError::Internal("clock outside the timestamp range".into()))?;
    if request.expires_at.is_some_and(|expires| expires > latest) {
        return invalid("expires_at must be within 100 years");
    }
    let (plaintext, hash) = generate()?;
    let token = ApiToken {
        token_id: Uuid::new_v4(),
        name: request.name,
        scope: request.scope,
        source: request.source,
        pop: request.pop,
        created_at: now,
        created_by: actor.to_owned(),
        expires_at: request.expires_at,
        last_used_at: None,
        revoked_at: None,
        revoked_by: None,
    };
    repo.create_api_token(&token, &hash, &audit(actor, "api_token.create", &token))
        .await?;
    tracing::info!(token = %token.name, scope = %token.scope, created_by = %actor, "API token created");
    Ok((token, plaintext))
}

/// Revoke the named token with an `api_token.revoke` audit row. Revoking an
/// already revoked token returns it unchanged and writes no second row.
pub async fn revoke(
    repo: &dyn RepositoryTrait,
    name: &str,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<ApiToken> {
    if !is_valid_token_name(name) {
        return Err(PrefixdError::NotFound(format!("token {name:?} not found")));
    }
    // The audit row names the token; scope and binding come from the stored row.
    let stored = repo
        .list_api_tokens(None)
        .await?
        .into_iter()
        .find(|token| token.name == name)
        .ok_or_else(|| PrefixdError::NotFound(format!("token {name:?} not found")))?;
    let token = repo
        .revoke_api_token(name, actor, now, &audit(actor, "api_token.revoke", &stored))
        .await?
        .ok_or_else(|| PrefixdError::NotFound(format!("token {name:?} not found")))?;
    tracing::info!(token = %token.name, revoked_by = %actor, "API token revoked");
    Ok(token)
}

/// Verify a presented `Authorization: Bearer` credential.
///
/// - A value without the token format is refused before any query.
/// - Unknown, revoked and expired tokens get 401; a revoked or expired token
///   is logged at warn with its name, as a rotation signal.
/// - A token bound to another POP gets 403 naming the bound POP.
/// - A storage error gets 503, never 401.
///
/// Verification writes nothing: the caller stamps `last_used_at` with
/// [`record_use`] when [`use_due`] says so.
///
/// No message or log line carries the presented value or its hash.
pub async fn verify(
    repo: &dyn RepositoryTrait,
    presented: &[u8],
    local_pop: &str,
    now: DateTime<Utc>,
) -> Result<ApiToken> {
    let hash =
        parse(presented).ok_or_else(|| PrefixdError::Unauthorized("malformed API token".into()))?;
    let token = match repo.get_api_token_by_hash(&hash).await {
        Ok(Some(token)) => token,
        Ok(None) => return Err(PrefixdError::Unauthorized("invalid API token".into())),
        Err(error) => {
            tracing::error!(error = %error, "API token lookup failed");
            return Err(PrefixdError::CredentialStoreUnavailable);
        }
    };
    if token.revoked_at.is_some() {
        tracing::warn!(token = %token.name, "revoked API token presented");
        return Err(PrefixdError::Unauthorized("API token revoked".into()));
    }
    if token.is_expired(now) {
        tracing::warn!(token = %token.name, "expired API token presented");
        return Err(PrefixdError::Unauthorized("API token expired".into()));
    }
    if let Some(bound) = token.pop.as_deref()
        && bound != local_pop
    {
        tracing::warn!(token = %token.name, bound_pop = %bound, pop = %local_pop, "API token bound to another POP");
        return Err(PrefixdError::Forbidden(format!(
            "API token is bound to POP {bound:?}"
        )));
    }
    Ok(token)
}

/// Whether `last_used_at` is due for a stamp at `now`: at most once per
/// [`last_used_interval`] per token.
pub fn use_due(token: &ApiToken, now: DateTime<Utc>) -> bool {
    token
        .last_used_at
        .is_none_or(|used| used <= now - last_used_interval())
}

/// Stamp `last_used_at`, best-effort: a failure is logged and never fails a
/// request. The repository repeats the throttle, so concurrent requests write
/// at most once per interval. Only the active controller calls this; a standby
/// mutates nothing.
pub async fn record_use(
    repo: &dyn RepositoryTrait,
    token_id: Uuid,
    name: &str,
    now: DateTime<Utc>,
) {
    if let Err(error) = repo
        .touch_api_token(token_id, now, now - last_used_interval())
        .await
    {
        tracing::warn!(token = %name, error = %error, "failed to record API token use");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::MockRepository;
    use std::sync::atomic::Ordering::SeqCst;

    fn request(name: &str, scope: TokenScope, source: Option<&str>) -> NewToken {
        NewToken {
            name: name.into(),
            scope,
            source: source.map(Into::into),
            pop: None,
            expires_at: None,
        }
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + seconds, 0).unwrap()
    }

    #[test]
    fn generated_tokens_have_the_format_and_hash_they_claim() {
        let (token, hash) = generate().unwrap();
        assert_eq!(token.len(), TOKEN_PREFIX.len() + ENCODED_LEN);
        assert!(token.starts_with(TOKEN_PREFIX));
        assert!(
            token[TOKEN_PREFIX.len()..]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_eq!(parse(token.as_bytes()), Some(hash));
        assert_eq!(hash, super::hash(&token));
        assert_ne!(generate().unwrap().0, token, "two tokens must differ");
    }

    #[test]
    fn the_format_check_refuses_everything_else() {
        // Control: the all-zero secret has the format.
        let zero = format!("{TOKEN_PREFIX}{}A", "A".repeat(ENCODED_LEN - 1));
        assert!(parse(zero.as_bytes()).is_some());
        let body = &zero[TOKEN_PREFIX.len()..];
        for presented in [
            String::new(),
            body.to_owned(),
            format!("prefixd-{body}"),
            format!("PREFIXD_{body}"),
            format!("{zero}A"),
            zero[..zero.len() - 1].to_owned(),
            format!("{TOKEN_PREFIX}{}", "!".repeat(ENCODED_LEN)),
            format!("{TOKEN_PREFIX}{}=", &body[..ENCODED_LEN - 1]),
            // The last character carries 2 unused bits; 'B' sets one, so this
            // noncanonical spelling of the same secret is refused.
            format!("{TOKEN_PREFIX}{}B", &body[..ENCODED_LEN - 1]),
            format!(" {zero}"),
            format!("{zero} "),
        ] {
            assert_eq!(parse(presented.as_bytes()), None, "{presented:?}");
        }
    }

    #[tokio::test]
    async fn create_validates_and_stores_only_the_hash() {
        let repo = MockRepository::new();
        for (name, scope, source, message) in [
            ("", TokenScope::Operator, None, "name"),
            ("Upper", TokenScope::Operator, None, "name"),
            (&*"a".repeat(59), TokenScope::Operator, None, "name"),
            ("fnm", TokenScope::Ingest, None, "requires a source"),
            ("fnm", TokenScope::Ingest, Some("Bad"), "source must match"),
            (
                "ops",
                TokenScope::Operator,
                Some("fastnetmon"),
                "only an ingest",
            ),
            (
                "adm",
                TokenScope::Admin,
                Some("fastnetmon"),
                "only an ingest",
            ),
        ] {
            let error = create(&repo, request(name, scope, source), "admin", at(0))
                .await
                .unwrap_err();
            assert!(
                matches!(&error, PrefixdError::InvalidRequest(m) if m.contains(message)),
                "{name}: {error}"
            );
        }
        let mut bad_pop = request("ops", TokenScope::Operator, None);
        bad_pop.pop = Some("pop 1".into());
        assert!(create(&repo, bad_pop, "admin", at(0)).await.is_err());
        let mut past = request("ops", TokenScope::Operator, None);
        past.expires_at = Some(at(0));
        assert!(create(&repo, past, "admin", at(0)).await.is_err());
        assert!(repo.list_api_tokens(None).await.unwrap().is_empty());

        let longest = "a".repeat(58);
        let (token, plaintext) = create(
            &repo,
            request(&longest, TokenScope::Ingest, Some("fastnetmon")),
            "admin",
            at(0),
        )
        .await
        .unwrap();
        assert_eq!(token.created_by, "admin");
        assert_eq!(token.actor_id().len(), crate::domain::MAX_USERNAME_LEN);
        assert_eq!(
            repo.get_api_token_by_hash(&super::hash(&plaintext))
                .await
                .unwrap(),
            Some(token.clone())
        );
        let serialized = serde_json::to_string(&token).unwrap();
        assert!(!serialized.contains(&plaintext));
        assert!(!serialized.contains(&hex::encode(super::hash(&plaintext))));
        // Names are never reused, revoked or not.
        revoke(&repo, &longest, "admin", at(1)).await.unwrap();
        let error = create(
            &repo,
            request(&longest, TokenScope::Operator, None),
            "admin",
            at(2),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, PrefixdError::Conflict(_)), "{error}");
    }

    #[tokio::test]
    async fn revoke_is_idempotent_and_audits_once() {
        let repo = MockRepository::new();
        let (_, _) = create(
            &repo,
            request("fnm-pop1", TokenScope::Ingest, Some("fastnetmon")),
            "admin",
            at(0),
        )
        .await
        .unwrap();
        let first = revoke(&repo, "fnm-pop1", "admin", at(5)).await.unwrap();
        let second = revoke(&repo, "fnm-pop1", "other", at(9)).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(first.revoked_at, Some(at(5)));
        // A stamp after the revocation, from a request verified before it,
        // writes nothing.
        record_use(&repo, first.token_id, &first.name, at(100)).await;
        assert_eq!(
            repo.list_api_tokens(None).await.unwrap()[0].last_used_at,
            None
        );
        assert_eq!(first.revoked_by.as_deref(), Some("admin"));
        let audit = repo
            .list_audit(&crate::db::ListParams {
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        let actions: Vec<_> = audit.iter().map(|entry| entry.action.as_str()).collect();
        assert_eq!(
            actions.iter().filter(|a| **a == "api_token.revoke").count(),
            1
        );
        assert_eq!(
            actions.iter().filter(|a| **a == "api_token.create").count(),
            1
        );
        for entry in &audit {
            assert_eq!(entry.target_type.as_deref(), Some("api_token"));
            assert_eq!(entry.target_id.as_deref(), Some("fnm-pop1"));
            assert_eq!(entry.details["source"], "fastnetmon");
            assert_eq!(entry.details["scope"], "ingest");
        }
        assert!(matches!(
            revoke(&repo, "missing", "admin", at(9)).await,
            Err(PrefixdError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn verify_refuses_each_failure_with_its_status() {
        let repo = MockRepository::new();
        let mint = |name: &str, pop: Option<&str>, expires: Option<i64>| {
            let mut request = request(name, TokenScope::Operator, None);
            request.pop = pop.map(Into::into);
            request.expires_at = expires.map(at);
            create(&repo, request, "admin", at(0))
        };
        let (_, any_pop) = mint("any-pop", None, None).await.unwrap();
        let (_, pop_a) = mint("pop-a", Some("pop-a"), None).await.unwrap();
        let (_, expiring) = mint("expiring", None, Some(100)).await.unwrap();
        let (_, revoked) = mint("revoked", None, None).await.unwrap();
        revoke(&repo, "revoked", "admin", at(1)).await.unwrap();
        let status = |result: Result<ApiToken>| result.map(|t| t.name).map_err(|e| e.status_code());

        use axum::http::StatusCode;
        // A null-POP token works on both POPs; a POP-A token only on POP A.
        for pop in ["pop-a", "pop-b"] {
            assert_eq!(
                status(verify(&repo, any_pop.as_bytes(), pop, at(1)).await),
                Ok("any-pop".into())
            );
        }
        assert_eq!(
            status(verify(&repo, pop_a.as_bytes(), "pop-a", at(1)).await),
            Ok("pop-a".into())
        );
        let refused = verify(&repo, pop_a.as_bytes(), "pop-b", at(1))
            .await
            .unwrap_err();
        assert_eq!(refused.status_code(), StatusCode::FORBIDDEN);
        assert!(refused.to_string().contains("\"pop-a\""), "{refused}");
        // Expiry under controlled time: valid before, refused at and after.
        assert!(
            verify(&repo, expiring.as_bytes(), "pop-a", at(99))
                .await
                .is_ok()
        );
        for now in [100, 101] {
            let error = verify(&repo, expiring.as_bytes(), "pop-a", at(now))
                .await
                .unwrap_err();
            assert_eq!(error.status_code(), StatusCode::UNAUTHORIZED);
            assert!(error.to_string().contains("expired"), "{error}");
        }
        let error = verify(&repo, revoked.as_bytes(), "pop-a", at(2))
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), StatusCode::UNAUTHORIZED);
        assert!(error.to_string().contains("revoked"), "{error}");
        let (unknown, _) = generate().unwrap();
        assert_eq!(
            status(verify(&repo, unknown.as_bytes(), "pop-a", at(2)).await),
            Err(StatusCode::UNAUTHORIZED)
        );
        // A storage error is 503, but a malformed value never reaches storage.
        repo.fail_token_reads.store(true, SeqCst);
        assert_eq!(
            status(verify(&repo, any_pop.as_bytes(), "pop-a", at(2)).await),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        );
        for malformed in [&b"not-a-token"[..], b"", b"prefixd_short"] {
            assert_eq!(
                status(verify(&repo, malformed, "pop-a", at(2)).await),
                Err(StatusCode::UNAUTHORIZED)
            );
        }
        // No message carries the secret.
        repo.fail_token_reads.store(false, SeqCst);
        for (secret, now) in [(&pop_a, 1), (&expiring, 100), (&revoked, 2)] {
            let pop = if secret == &pop_a { "pop-b" } else { "pop-a" };
            let error = verify(&repo, secret.as_bytes(), pop, at(now))
                .await
                .unwrap_err()
                .to_string();
            assert!(!error.contains(secret.as_str()), "{error}");
            assert!(!error.contains(&secret[TOKEN_PREFIX.len()..]), "{error}");
        }
    }

    #[tokio::test]
    async fn last_used_is_throttled_and_skipped_on_a_standby() {
        let repo = MockRepository::new();
        let (_, token) = create(
            &repo,
            request("ops", TokenScope::Operator, None),
            "admin",
            at(0),
        )
        .await
        .unwrap();
        let last_used = || async { repo.list_api_tokens(None).await.unwrap()[0].last_used_at };
        // What the active controller does per request: verify, then stamp
        // when due. A standby only verifies, and verification writes nothing.
        let active = |now: DateTime<Utc>| {
            let (repo, token) = (&repo, &token);
            async move {
                let verified = verify(repo, token.as_bytes(), "p", now).await.unwrap();
                if use_due(&verified, now) {
                    record_use(repo, verified.token_id, &verified.name, now).await;
                }
            }
        };
        verify(&repo, token.as_bytes(), "p", at(10)).await.unwrap();
        assert_eq!(last_used().await, None);
        // Written once, then not again within the interval.
        active(at(10)).await;
        assert_eq!(last_used().await, Some(at(10)));
        active(at(69)).await;
        assert_eq!(last_used().await, Some(at(10)));
        active(at(70)).await;
        assert_eq!(last_used().await, Some(at(70)));
        // A failed stamp never fails the request.
        repo.fail_token_touches.store(true, SeqCst);
        active(at(200)).await;
        assert_eq!(last_used().await, Some(at(70)));
    }
}
