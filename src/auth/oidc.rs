//! Dashboard sign-in against the deployment's configured OIDC issuer.
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Redirect,
};
use chrono::Utc;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IdToken, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    Scope, TokenResponse, core::*, reqwest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower_sessions::{Expiry, Session, cookie::time::OffsetDateTime};

use super::AuthSession;
use crate::{AppState, config::OidcConfig, domain::OperatorRole};

type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;
type ClaimsToken =
    IdToken<Claims, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Claims(BTreeMap<String, Value>);
impl openidconnect::AdditionalClaims for Claims {}

#[derive(Serialize, Deserialize)]
struct Pending {
    state: String,
    nonce: String,
    verifier: String,
    expires: i64,
    config_version: String,
}

#[derive(Deserialize)]
pub struct Callback {
    state: String,
    code: String,
}

fn token_auth_method(
    methods: Option<&[CoreClientAuthMethod]>,
) -> anyhow::Result<openidconnect::AuthType> {
    use CoreClientAuthMethod::{ClientSecretBasic, ClientSecretPost};
    match methods {
        None => Ok(openidconnect::AuthType::BasicAuth),
        Some(methods) if methods.contains(&ClientSecretBasic) => {
            Ok(openidconnect::AuthType::BasicAuth)
        }
        Some(methods) if methods.contains(&ClientSecretPost) => {
            Ok(openidconnect::AuthType::RequestBody)
        }
        _ => anyhow::bail!("issuer does not advertise a supported token authentication method"),
    }
}

fn requires_https(issuer: &IssuerUrl) -> bool {
    issuer.url().scheme() == "https"
}

async fn client(config: &OidcConfig) -> anyhow::Result<(Client, reqwest::Client)> {
    let secret = std::env::var(&config.client_secret_env)?;
    anyhow::ensure!(!secret.is_empty());
    let issuer = IssuerUrl::new(config.issuer.clone())?;
    let https = requires_https(&issuer);
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(https)
        .timeout(Duration::from_secs(10))
        .build()?;
    let metadata = CoreProviderMetadata::discover_async(issuer, &http).await?;
    anyhow::ensure!(metadata.authorization_endpoint().url().scheme() == "https" || !https);
    let method = token_auth_method(
        metadata
            .token_endpoint_auth_methods_supported()
            .map(Vec::as_slice),
    )?;
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(secret)),
    )
    .set_auth_type(method)
    .set_redirect_uri(RedirectUrl::new(config.redirect_uri.clone())?);
    Ok((client, http))
}

#[utoipa::path(get, path = "/v1/auth/oidc/login", tag = "auth", responses(
    (status = 303, description = "Redirect to the configured identity provider"),
    (status = 404, description = "OIDC is disabled"),
    (status = 503, description = "OIDC provider unavailable")
))]
pub async fn start(
    State(state): State<Arc<AppState>>,
    session: Session,
) -> Result<Redirect, StatusCode> {
    let config = state
        .settings
        .http
        .auth
        .oidc
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let (client, _) = client(config)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut auth = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge);
    for scope in &config.extra_scopes {
        auth = auth.add_scope(Scope::new(scope.clone()));
    }
    let (url, token, nonce) = auth.url();
    session
        .insert(
            "oidc.pending",
            Pending {
                state: token.secret().clone(),
                nonce: nonce.secret().clone(),
                verifier: verifier.secret().clone(),
                expires: Utc::now().timestamp() + 300,
                config_version: config.session_prefix(),
            },
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Redirect::to(url.as_str()))
}

fn mapped_role(config: &OidcConfig, claims: &Claims) -> Result<OperatorRole, &'static str> {
    if claims
        .0
        .get("_claim_names")
        .and_then(|v| v.get(&config.role_claim))
        .is_some()
        || (config.role_claim == "groups" && claims.0.contains_key("hasgroups"))
    {
        return Err("incomplete role claim");
    }
    let values = claims
        .0
        .get(&config.role_claim)
        .ok_or("missing role claim")?
        .as_array()
        .ok_or("role claim must be a string array")?;
    let mut role = None;
    for value in values {
        let name = value.as_str().ok_or("invalid role claim element")?;
        if let Some(next) = config.role_mappings.get(name) {
            if role.is_some_and(|prior| prior != next) {
                return Err("conflicting mapped roles");
            }
            role = Some(next);
        }
    }
    role.cloned().ok_or("no mapped role")
}

#[utoipa::path(get, path = "/v1/auth/oidc/callback", tag = "auth", params(
    ("state" = String, Query, description = "Browser login state"),
    ("code" = String, Query, description = "Single-use authorization code")
), responses(
    (status = 303, description = "Dashboard session created"),
    (status = 401, description = "Invalid OIDC response or expired login"),
    (status = 403, description = "Role mapping denied access"),
    (status = 404, description = "OIDC is disabled"),
    (status = 503, description = "OIDC provider unavailable")
))]
pub async fn callback(
    State(state): State<Arc<AppState>>,
    session: Session,
    mut auth: AuthSession,
    Query(query): Query<Callback>,
) -> Result<Redirect, StatusCode> {
    let config = state
        .settings
        .http
        .auth
        .oidc
        .as_ref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let pending: Pending = session
        .remove("oidc.pending")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if query.state != pending.state
        || Utc::now().timestamp() >= pending.expires
        || pending.config_version != config.session_prefix()
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (client, http) = client(config)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let tokens = client
        .exchange_code(AuthorizationCode::new(query.code))
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .set_pkce_verifier(PkceCodeVerifier::new(pending.verifier))
        .request_async(&http)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    // Deserialize the signed token with the deployment-specific additional claims.
    let token: ClaimsToken = tokens
        .id_token()
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string()
        .parse()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let claims = token
        .claims(&client.id_token_verifier(), &Nonce::new(pending.nonce))
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let role = mapped_role(config, claims.additional_claims()).map_err(|reason| {
        tracing::warn!(reason, "OIDC login denied");
        StatusCode::FORBIDDEN
    })?;
    let expires = claims
        .expiration()
        .min(Utc::now() + chrono::Duration::hours(1));
    let expiry = expires.timestamp();
    let deadline =
        OffsetDateTime::from_unix_timestamp(expiry).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let version = format!("{}{}", pending.config_version, uuid::Uuid::new_v4());
    let operator = state
        .repo
        .upsert_oidc_operator(
            &config.issuer,
            claims.subject().as_str(),
            role,
            &version,
            expires,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    auth.login(&operator)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    session.set_expiry(Some(Expiry::AtDateTime(deadline)));
    // The store's absolute expiry also bounds any upgraded WebSocket.
    session
        .insert("oidc.deadline", expiry)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Redirect::to("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepted_https_spellings_enforce_tls_on_provider_endpoints() {
        for scheme in ["https", "HTTPS", "hTtPs"] {
            let issuer = IssuerUrl::new(format!("{scheme}://sso.example.org")).unwrap();
            assert!(requires_https(&issuer));
        }
    }

    #[test]
    fn token_authentication_uses_supported_secret_methods() {
        use CoreClientAuthMethod::{ClientSecretBasic, ClientSecretPost, PrivateKeyJwt};
        use openidconnect::AuthType;
        assert!(matches!(token_auth_method(None), Ok(AuthType::BasicAuth)));
        assert!(matches!(
            token_auth_method(Some(&[ClientSecretPost, ClientSecretBasic])),
            Ok(AuthType::BasicAuth)
        ));
        assert!(matches!(
            token_auth_method(Some(&[ClientSecretPost])),
            Ok(AuthType::RequestBody)
        ));
        assert!(token_auth_method(Some(&[PrivateKeyJwt])).is_err());
        assert!(token_auth_method(Some(&[])).is_err());
    }

    #[test]
    fn directory_assignments_must_resolve_to_one_role() {
        let config = OidcConfig {
            issuer: "https://sso.example.org".into(),
            client_id: "prefixd".into(),
            client_secret_env: "OIDC_SECRET".into(),
            redirect_uri: "https://prefixd.example.org/callback".into(),
            extra_scopes: vec![],
            role_claim: "groups".into(),
            role_mappings: [
                ("audit".into(), OperatorRole::Viewer),
                ("engineering".into(), OperatorRole::Viewer),
                ("admin".into(), OperatorRole::Admin),
                ("ops".into(), OperatorRole::Operator),
            ]
            .into(),
        };
        for (value, expected) in [
            (
                json!({"groups":["audit","engineering"]}),
                Some(OperatorRole::Viewer),
            ),
            (json!({"groups":["admin"]}), Some(OperatorRole::Admin)),
            (json!({"groups":["ops"]}), Some(OperatorRole::Operator)),
            (json!({"groups":["admin","ops"]}), None),
            (json!({"groups":["ADMIN"]}), None),
            (json!({"groups":"ops"}), None),
            (json!({}), None),
            (json!({"groups":["admin",42]}), None),
            (
                json!({"groups":["admin"],"_claim_names":{"groups":"source"}}),
                None,
            ),
        ] {
            let claims = serde_json::from_value(value).unwrap();
            assert_eq!(mapped_role(&config, &claims).ok(), expected);
        }
    }
}
