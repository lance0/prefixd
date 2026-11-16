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
use crate::domain::{ApiToken, Operator, OperatorRole, TokenScope};
use crate::error::PrefixdError;

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
        password_hash: String::new(),
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
            password_hash: String::new(),
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
                    let token = crate::auth::token::verify(
                        state.repo.as_ref(),
                        presented,
                        &state.settings.pop,
                        state.fence.is_active(),
                        chrono::Utc::now(),
                    )
                    .await?;
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

/// The principal of an ingest route, which may be an ingest token.
#[derive(Clone, Debug)]
pub struct IngestPrincipal(pub AuthPrincipal);

impl FromRequestParts<Arc<AppState>> for IngestPrincipal {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        extract(parts, state)
            .await
            .map(Self)
            .map_err(|error| AppError(error).into_response())
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

/// The ingest routes accept an ingest token or an Operator. Ingest endpoints
/// are mutations even when they carry detector metadata, so Viewers are refused.
pub fn require_ingest(principal: &AuthPrincipal) -> Result<(), PrefixdError> {
    if let Some(Principal::Ingest { .. }) = principal.0 {
        return Ok(());
    }
    match require_role(principal, OperatorRole::Operator) {
        Ok(_) => Ok(()),
        Err(StatusCode::FORBIDDEN) => Err(PrefixdError::Forbidden(
            "operator role or an ingest token required".into(),
        )),
        Err(_) => Err(PrefixdError::Unauthorized("authentication required".into())),
    }
}

/// Token management needs an Admin session. No token can call it, admin
/// tokens included: a stolen admin token that could mint replacements would
/// survive its own revocation.
pub fn require_admin_session(principal: &AuthPrincipal) -> Result<Operator, PrefixdError> {
    match &principal.0 {
        None => Err(PrefixdError::Unauthorized("authentication required".into())),
        Some(Principal::Operator(operator, Credential::Session))
            if operator.role == OperatorRole::Admin =>
        {
            Ok(operator.clone())
        }
        Some(_) => Err(PrefixdError::Forbidden(
            "token management requires an Admin session".into(),
        )),
    }
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
        assert!(require_ingest(&operator(OperatorRole::Operator, Credential::Token)).is_ok());
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
}
