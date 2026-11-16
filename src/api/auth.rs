//! Credential resolution (ADR 034 §2) and the authorization checks that read it.
//!
//! [`AuthPrincipal`] resolves the request's identity once and stores it in the
//! request extensions. `require_auth` and `require_role` stay synchronous and
//! read it. Only `Authorization: Bearer` is a token credential, and a Bearer
//! request never loads the session: [`strip_cookie_for_bearer`] removes the
//! `Cookie` header before the session layer runs.

use axum::extract::{FromRequestParts, Request, State};
use axum::http::{
    HeaderMap, StatusCode,
    header::{AUTHORIZATION, COOKIE},
    request::Parts,
};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use super::handlers::AppError;
use crate::AppState;
use crate::auth::AuthSession;
use crate::config::AuthMode;
use crate::domain::{ApiToken, Operator, OperatorRole, TOKEN_ACTOR_PREFIX, TokenScope};
use crate::error::PrefixdError;
use crate::observability::{ActorType, CreationActor};

/// How an operator-equivalent principal authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credential {
    Session,
    Token,
    Mtls,
    Anonymous,
}

/// An authenticated identity.
#[derive(Clone, Debug)]
pub enum Principal {
    /// A session, an operator or admin token, an mTLS client, or `none` mode.
    Operator(Operator, Credential),
    /// An ingest token. It is not a role: only the ingest routes accept it.
    Ingest {
        token: String,
        source: String,
        pop: Option<String>,
    },
}

/// The request's principal, or `None` when it presented no credential.
#[derive(Clone, Debug)]
pub struct AuthPrincipal(pub Option<Principal>);

/// The `Authorization: Bearer` credential, if the request is a token request.
/// The outer `Some` means some `Authorization` header uses the Bearer scheme
/// (case-insensitive); the inner value is `None` when several `Authorization`
/// headers make the credential ambiguous. Other schemes are not token
/// credentials, so a proxy's `Basic` header leaves the session in charge.
fn bearer(headers: &HeaderMap) -> Option<Option<&[u8]>> {
    let scheme_is_bearer = |value: &[u8]| {
        let scheme = value.split(|c| *c == b' ').next().unwrap_or_default();
        scheme.eq_ignore_ascii_case(b"bearer")
    };
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let first = values.next()?;
    let rest: Vec<_> = values.collect();
    if !scheme_is_bearer(first.as_bytes()) && !rest.iter().any(|v| scheme_is_bearer(v.as_bytes())) {
        return None;
    }
    if !rest.is_empty() {
        return Some(None);
    }
    let value = first.as_bytes();
    Some(Some(value.get(b"bearer ".len()..).unwrap_or_default()))
}

/// Remove the `Cookie` header from token requests in `credentials` mode, before
/// the session layer would load the session. An invalid token then gets 401
/// even beside a valid cookie, a stale cookie during a database outage cannot
/// fail a valid token request, and a failed session load cannot clear the
/// browser's cookie.
pub async fn strip_cookie_for_bearer(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    if state.settings.http.auth.mode == AuthMode::Credentials && bearer(request.headers()).is_some()
    {
        request.headers_mut().remove(COOKIE);
    }
    next.run(request).await
}

fn synthetic(username: &str) -> Operator {
    Operator {
        operator_id: uuid::Uuid::nil(),
        username: username.to_string(),
        password_hash: Default::default(),
        role: OperatorRole::Admin,
        created_at: chrono::Utc::now(),
        created_by: None,
        last_login_at: None,
    }
}

fn token_principal(token: ApiToken) -> Result<Principal, PrefixdError> {
    let role = match token.scope {
        TokenScope::Ingest => {
            let source = token.source.ok_or_else(|| {
                PrefixdError::Internal(format!("ingest token {:?} has no source", token.name))
            })?;
            return Ok(Principal::Ingest {
                token: token.name,
                source,
                pop: token.pop,
            });
        }
        TokenScope::Operator => OperatorRole::Operator,
        TokenScope::Admin => OperatorRole::Admin,
    };
    Ok(Principal::Operator(
        Operator {
            operator_id: token.token_id,
            username: token.actor_id(),
            password_hash: Default::default(),
            role,
            created_at: token.created_at,
            created_by: Some(token.created_by),
            last_login_at: None,
        },
        Credential::Token,
    ))
}

impl AuthPrincipal {
    /// Resolve the principal. `none` mode is anonymous Admin and ignores
    /// credentials; `mtls` mode is Admin for every verified client certificate
    /// and consults no token. In `credentials` mode a Bearer header is the
    /// only credential considered when present; otherwise the session applies.
    pub async fn resolve(
        state: &AppState,
        headers: &HeaderMap,
        session: Option<&AuthSession>,
    ) -> Result<Self, PrefixdError> {
        let principal = match state.settings.http.auth.mode {
            AuthMode::None => Some(Principal::Operator(
                synthetic("anonymous"),
                Credential::Anonymous,
            )),
            AuthMode::Mtls => Some(Principal::Operator(
                synthetic("mtls-client"),
                Credential::Mtls,
            )),
            AuthMode::Credentials => match bearer(headers) {
                None => session
                    .and_then(|session| session.user.clone())
                    .map(|operator| Principal::Operator(operator, Credential::Session)),
                Some(None) => {
                    return Err(PrefixdError::Unauthorized(
                        "send exactly one Authorization header".into(),
                    ));
                }
                Some(Some(presented)) => {
                    let now = chrono::Utc::now();
                    let token = crate::auth::token::verify(
                        state.repo.as_ref(),
                        presented,
                        &state.settings.pop,
                        now,
                    )
                    .await?;
                    // Fire and forget, so a slow pool never delays the request.
                    // A standby mutates nothing: the fence is checked here and
                    // again right before the write, which may run after a loss.
                    if state.fence.is_active() && crate::auth::token::use_due(&token, now) {
                        let (repo, fence, id, name) = (
                            state.repo.clone(),
                            state.fence.clone(),
                            token.token_id,
                            token.name.clone(),
                        );
                        tokio::spawn(async move {
                            if fence.is_active() {
                                crate::auth::token::record_use(repo.as_ref(), id, &name, now).await;
                            }
                        });
                    }
                    Some(token_principal(token)?)
                }
            },
        };
        Ok(Self(principal))
    }
}

/// Resolve once per request; later extractions reuse the stored principal.
async fn extract(parts: &mut Parts, state: &AppState) -> Result<AuthPrincipal, PrefixdError> {
    if let Some(resolved) = parts.extensions.get::<AuthPrincipal>() {
        return Ok(resolved.clone());
    }
    let resolved =
        AuthPrincipal::resolve(state, &parts.headers, parts.extensions.get::<AuthSession>())
            .await?;
    parts.extensions.insert(resolved.clone());
    Ok(resolved)
}

/// Every route except the ingest routes extracts this. It refuses an ingest
/// token with 403 before the body is read, so a route reaches ingest tokens
/// only by extracting [`IngestPrincipal`] instead; `require_auth` and
/// `require_role` refuse them again.
impl FromRequestParts<Arc<AppState>> for AuthPrincipal {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let resolved = extract(parts, state)
            .await
            .map_err(|error| AppError(error).into_response())?;
        if let Some(Principal::Ingest { token, .. }) = &resolved.0 {
            tracing::warn!(token = %token, "ingest token refused outside the ingest routes");
            return Err(AppError(PrefixdError::Forbidden(
                "an ingest token reaches only the ingest routes".into(),
            ))
            .into_response());
        }
        Ok(resolved)
    }
}

/// The principal of an ingest route, which may be an ingest token. Only a
/// principal that can hold a source grant gets past extraction (see
/// [`require_ingest`]), so an Operator gets 403 and a request without a
/// credential 401 before the body is parsed.
#[derive(Clone, Debug)]
pub struct IngestPrincipal(pub AuthPrincipal);

impl FromRequestParts<Arc<AppState>> for IngestPrincipal {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let principal = extract(parts, state)
            .await
            .map_err(|error| AppError(error).into_response())?;
        require_ingest(&principal).map_err(|error| AppError(error).into_response())?;
        Ok(Self(principal))
    }
}

/// Any operator-equivalent principal, Viewer and up. Ingest tokens get 403.
pub fn require_auth(principal: &AuthPrincipal) -> Result<(), StatusCode> {
    require_role(principal, OperatorRole::Viewer).map(drop)
}

/// The operator when its role suffices: 401 without a principal, 403 for an
/// insufficient role and for every ingest token.
pub fn require_role(
    principal: &AuthPrincipal,
    required_role: OperatorRole,
) -> Result<Operator, StatusCode> {
    match &principal.0 {
        None => Err(StatusCode::UNAUTHORIZED),
        Some(Principal::Ingest { token, .. }) => {
            tracing::warn!(token = %token, "ingest token refused outside the ingest routes");
            Err(StatusCode::FORBIDDEN)
        }
        Some(Principal::Operator(operator, _)) if operator.role.has_permission(&required_role) => {
            Ok(operator.clone())
        }
        Some(Principal::Operator(operator, _)) => {
            tracing::warn!(
                username = %operator.username,
                role = %operator.role,
                required = %required_role,
                "insufficient permissions"
            );
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// The principals an ingest route can grant a source to: an ingest token, or
/// an Admin (session, admin token, mTLS client or `none` mode). A route that
/// must parse its body to learn the claimed source checks this first, so an
/// Operator or Viewer gets 403 before its body is read. [`authorize_ingest`]
/// then binds the source.
pub fn require_ingest(principal: &AuthPrincipal) -> Result<(), PrefixdError> {
    match &principal.0 {
        None => Err(PrefixdError::Unauthorized("authentication required".into())),
        Some(Principal::Ingest { .. }) => Ok(()),
        Some(Principal::Operator(operator, _))
            if operator.role.has_permission(&OperatorRole::Admin) =>
        {
            Ok(())
        }
        Some(Principal::Operator(operator, _)) => {
            refused_operator(operator);
            Err(PrefixdError::Forbidden(
                "ingest routes need an ingest token bound to the event source, or an Admin".into(),
            ))
        }
    }
}

fn refused_operator(operator: &Operator) {
    tracing::warn!(username = %operator.username, role = %operator.role,
        "refused an ingest request from a principal without a source grant");
    crate::observability::metrics::EVENTS_REJECTED
        .with_label_values(&["unbound", "source_not_bound"])
        .inc();
}

/// The source an ingest request acts as, and the actor it is audited as
/// (ADR 034 §4 and §6). Only this module builds one: [`authorize_ingest`]
/// from a principal, [`authorize_webhook_hmac`] from a verified adapter
/// signature, and a test constructor. Every ingest route sets the event's or
/// signal's `source` from the grant, so every source-keyed check (blackhole and
/// prefix allowlists, correlation weight, `min_sources`, corroborating mode and
/// the unban lookup) reads an authorized source.
#[derive(Clone, Debug)]
pub struct SourceGrant {
    source: String,
    actor_type: ActorType,
    actor_id: String,
}

impl SourceGrant {
    pub fn source(&self) -> &str {
        &self.source
    }

    /// `detector` for an ingest token or an HMAC adapter, `operator` for an
    /// Admin who claimed the source.
    pub fn actor_type(&self) -> ActorType {
        self.actor_type
    }

    /// `token:<name>`, `webhook:<adapter>`, or the Admin's identity.
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    pub fn creation_actor(&self) -> CreationActor {
        CreationActor::Detector {
            source: self.source.clone(),
            actor_type: self.actor_type,
            actor_id: self.actor_id.clone(),
        }
    }

    /// A grant for unit tests that drive the ingest functions directly.
    #[cfg(test)]
    pub fn for_test(source: &str) -> Self {
        Self {
            source: source.into(),
            actor_type: ActorType::Detector,
            actor_id: format!("{TOKEN_ACTOR_PREFIX}test"),
        }
    }
}

/// Grant `claimed` to the principal (ADR 034 §4). An ingest token gets only
/// the source it is bound to; its POP binding was checked when it was
/// verified. An Admin, including an mTLS client and `none` mode, may claim any
/// source and is audited as itself. An Operator and a Viewer get 403, and a
/// request without a credential gets 401. A refusal is counted under the bound
/// source, never the claimed one, so a caller cannot grow label cardinality.
pub fn authorize_ingest(
    principal: &AuthPrincipal,
    claimed: &str,
) -> Result<SourceGrant, PrefixdError> {
    match &principal.0 {
        None => Err(PrefixdError::Unauthorized("authentication required".into())),
        Some(Principal::Ingest { token, source, .. }) if source == claimed => Ok(SourceGrant {
            source: source.clone(),
            actor_type: ActorType::Detector,
            actor_id: format!("{TOKEN_ACTOR_PREFIX}{token}"),
        }),
        Some(Principal::Ingest { token, source, .. }) => {
            tracing::warn!(token = %token, bound = %source, claimed = %claimed,
                "refused an ingest token claiming a source it is not bound to");
            crate::observability::metrics::EVENTS_REJECTED
                .with_label_values(&[source.as_str(), "source_not_bound"])
                .inc();
            Err(PrefixdError::SourceNotBound {
                claimed: claimed.into(),
                bound: Some(source.clone()),
            })
        }
        Some(Principal::Operator(operator, _))
            if operator.role.has_permission(&OperatorRole::Admin) =>
        {
            Ok(SourceGrant {
                source: claimed.into(),
                actor_type: ActorType::Operator,
                actor_id: operator.username.clone(),
            })
        }
        Some(Principal::Operator(operator, _)) => {
            refused_operator(operator);
            Err(PrefixdError::SourceNotBound {
                claimed: claimed.into(),
                bound: None,
            })
        }
    }
}

/// Grant an HMAC webhook adapter its own name (ADR 034 §4). The adapter's
/// secret is the credential, so no principal is involved and `Authorization`
/// is ignored. `signature` is the configured header's value; a missing or
/// mismatched signature gets 401.
pub fn authorize_webhook_hmac(
    adapter: &str,
    secret: &[u8],
    body: &[u8],
    signature: Option<&str>,
) -> Result<SourceGrant, PrefixdError> {
    let signature = signature
        .ok_or_else(|| PrefixdError::Unauthorized("missing HMAC signature header".into()))?;
    if !crate::correlation::verify_hmac_sha256(secret, body, signature) {
        return Err(PrefixdError::Unauthorized(
            "HMAC signature verification failed".into(),
        ));
    }
    Ok(SourceGrant {
        source: adapter.into(),
        actor_type: ActorType::Detector,
        actor_id: format!("{WEBHOOK_ACTOR_PREFIX}{adapter}"),
    })
}

/// The audit actor prefix of an HMAC webhook adapter, `webhook:<adapter>`.
pub const WEBHOOK_ACTOR_PREFIX: &str = "webhook:";

/// Identity management needs a session: an operator signed in with a
/// password. It covers API tokens, operator accounts and passwords. No token
/// can reach it, admin tokens included, and neither can an mTLS client or
/// `none` mode: a stolen admin token that could mint a token, create an Admin
/// operator or reset a password could sign in and survive its own revocation.
/// `prefixdctl` on the local database is the other path.
pub fn require_session(
    principal: &AuthPrincipal,
    required_role: OperatorRole,
) -> Result<Operator, PrefixdError> {
    match &principal.0 {
        None => Err(PrefixdError::Unauthorized("authentication required".into())),
        Some(Principal::Operator(operator, Credential::Session))
            if operator.role.has_permission(&required_role) =>
        {
            Ok(operator.clone())
        }
        Some(Principal::Operator(operator, Credential::Session)) => {
            tracing::warn!(
                username = %operator.username,
                role = %operator.role,
                required = %required_role,
                "insufficient permissions"
            );
            Err(PrefixdError::Forbidden(format!(
                "identity management requires a {required_role} session"
            )))
        }
        Some(_) => Err(PrefixdError::Forbidden(
            "identity management requires a signed-in session; tokens, mTLS clients and auth mode none cannot manage tokens, operators or passwords".into(),
        )),
    }
}

/// [`require_session`] with the Admin role: tokens and operator accounts.
pub fn require_admin_session(principal: &AuthPrincipal) -> Result<Operator, PrefixdError> {
    require_session(principal, OperatorRole::Admin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn only_the_bearer_scheme_is_a_token_credential() {
        assert_eq!(bearer(&headers(&[])), None);
        for other in [
            "Basic dXNlcjpwYXNz",
            "Token prefixd_x",
            "Bearerx y",
            "Digest x",
        ] {
            assert_eq!(bearer(&headers(&[other])), None, "{other}");
        }
        for (value, credential) in [
            ("Bearer prefixd_x", &b"prefixd_x"[..]),
            ("bearer prefixd_x", b"prefixd_x"),
            ("BEARER prefixd_x", b"prefixd_x"),
            ("Bearer", b""),
            ("Bearer  two-spaces", b" two-spaces"),
        ] {
            assert_eq!(
                bearer(&headers(&[value])),
                Some(Some(credential)),
                "{value}"
            );
        }
        // A Bearer header among several is ambiguous, never a fallback.
        assert_eq!(bearer(&headers(&["Basic a", "Bearer b"])), Some(None));
        assert_eq!(bearer(&headers(&["Bearer a", "Bearer b"])), Some(None));
        assert_eq!(bearer(&headers(&["Basic a", "Basic b"])), None);
    }

    fn operator(role: OperatorRole, credential: Credential) -> AuthPrincipal {
        let mut operator = synthetic("someone");
        operator.role = role;
        AuthPrincipal(Some(Principal::Operator(operator, credential)))
    }

    #[test]
    fn ingest_tokens_reach_only_the_ingest_check() {
        let ingest = AuthPrincipal(Some(Principal::Ingest {
            token: "fnm".into(),
            source: "fastnetmon".into(),
            pop: None,
        }));
        assert_eq!(require_auth(&ingest), Err(StatusCode::FORBIDDEN));
        for role in [
            OperatorRole::Viewer,
            OperatorRole::Operator,
            OperatorRole::Admin,
        ] {
            assert_eq!(
                require_role(&ingest, role).unwrap_err(),
                StatusCode::FORBIDDEN
            );
        }
        assert!(require_ingest(&ingest).is_ok());
        assert!(matches!(
            require_admin_session(&ingest),
            Err(PrefixdError::Forbidden(_))
        ));

        let none = AuthPrincipal(None);
        assert_eq!(require_auth(&none), Err(StatusCode::UNAUTHORIZED));
        assert!(matches!(
            require_ingest(&none),
            Err(PrefixdError::Unauthorized(_))
        ));
        let viewer = operator(OperatorRole::Viewer, Credential::Session);
        assert!(matches!(
            require_ingest(&viewer),
            Err(PrefixdError::Forbidden(_))
        ));
        for credential in [Credential::Session, Credential::Token] {
            assert!(matches!(
                require_ingest(&operator(OperatorRole::Operator, credential)),
                Err(PrefixdError::Forbidden(_))
            ));
        }
        for credential in [
            Credential::Session,
            Credential::Token,
            Credential::Mtls,
            Credential::Anonymous,
        ] {
            assert!(require_ingest(&operator(OperatorRole::Admin, credential)).is_ok());
        }
    }

    #[test]
    fn token_management_needs_an_admin_session() {
        assert!(require_admin_session(&operator(OperatorRole::Admin, Credential::Session)).is_ok());
        for credential in [Credential::Token, Credential::Mtls, Credential::Anonymous] {
            assert!(
                matches!(
                    require_admin_session(&operator(OperatorRole::Admin, credential)),
                    Err(PrefixdError::Forbidden(_))
                ),
                "{credential:?}"
            );
        }
        assert!(matches!(
            require_admin_session(&operator(OperatorRole::Operator, Credential::Session)),
            Err(PrefixdError::Forbidden(_))
        ));
    }

    /// A stamp spawned while the fence was held, but not yet run when the
    /// fence is lost, writes nothing. This runtime is single-threaded and the
    /// mock repository never waits, so the spawned stamp cannot run before the
    /// response returns; it runs only when the test yields, after the loss.
    #[tokio::test]
    async fn a_stamp_pending_when_the_fence_is_lost_does_not_write() {
        use crate::db::{MockRepository, RepositoryTrait};
        use tower::ServiceExt;

        let mut settings: crate::config::Settings =
            crate::config::parse_yaml(include_str!("../../configs/prefixd.yaml")).unwrap();
        settings.bgp.mode = crate::config::BgpMode::Mock;
        settings.bgp.rustbgpd = None;
        settings.http.auth.mode = AuthMode::Credentials;
        let repo = Arc::new(MockRepository::new());
        let token = repo.mint_token_for_test("automation", TokenScope::Operator, None);
        let fence = Arc::new(crate::fence::ControllerFence::new(true));
        let state = AppState::new(
            settings,
            crate::config::Inventory::new(vec![]),
            crate::config::Playbooks { playbooks: vec![] },
            repo.clone(),
            Arc::new(crate::bgp::MockAnnouncer::new()),
            ".".into(),
        )
        .unwrap()
        .with_fence(fence.clone())
        .unwrap();
        let app = crate::api::create_test_router(state);
        let request = || {
            axum::http::Request::get("/v1/mitigations")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let stamped = || async { repo.list_api_tokens(None).await.unwrap()[0].last_used_at };
        let settle = || async {
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        };

        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            stamped().await,
            None,
            "precondition: the stamp is still pending"
        );
        fence.set(false);
        settle().await;
        assert_eq!(
            stamped().await,
            None,
            "a stamp written after the fence was lost"
        );

        // Control: with the fence held throughout, the same request stamps.
        fence.set(true);
        let response = app.oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        settle().await;
        assert!(stamped().await.is_some());
    }
}
