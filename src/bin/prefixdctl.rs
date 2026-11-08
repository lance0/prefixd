#![forbid(unsafe_code)]
#![deny(clippy::allow_attributes_without_reason)]

use argon2::{Argon2, PasswordHasher};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "prefixdctl", about = "Control CLI for prefixd", version)]
struct Cli {
    /// prefixd API endpoint
    #[arg(short, long, default_value = "http://127.0.0.1", env = "PREFIXD_API")]
    api: String,

    /// Bearer token for authentication
    #[arg(short, long, env = "PREFIXD_API_TOKEN")]
    token: Option<String>,

    /// Cookie header from an authenticated administrator session
    #[arg(long, env = "PREFIXD_SESSION_COOKIE", hide_env_values = true)]
    session_cookie: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Default, clap::ValueEnum)]
enum OutputFormat {
    #[default]
    Table,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect or explicitly re-arm configured scrubber profiles
    #[command(subcommand)]
    Scrubbers(ScrubberCommands),
    /// Preview, create or withdraw a manual guarded diversion
    #[command(subcommand)]
    Diversions(DiversionCommands),
    /// Show daemon status and health
    Status,

    /// Manage mitigations
    #[command(subcommand)]
    Mitigations(MitigationCommands),

    /// Manage safelist
    #[command(subcommand)]
    Safelist(SafelistCommands),

    /// Manage operators (direct DB access, for initial setup)
    #[command(subcommand)]
    Operators(OperatorCommands),

    /// Show BGP peer status
    Peers,

    /// Observe the configured BGP speaker
    #[command(subcommand)]
    Speaker(SpeakerCommands),

    /// Reload configuration (inventory, playbooks)
    Reload,

    /// Show applied database migrations (requires DATABASE_URL)
    Migrations,

    /// Send a corroborating signal (ADR 021). Source must be configured
    /// with mode=corroborating in correlation.yaml.
    SendCorroborator {
        /// Signal source name (must match correlation.yaml entry)
        #[arg(short, long)]
        source: String,

        /// Optional vector narrower (udp_flood, syn_flood, ...)
        #[arg(short, long)]
        vector: Option<String>,

        /// Customer ID to match on
        #[arg(long)]
        customer_id: Option<String>,

        /// POP to match on
        #[arg(long)]
        pop: Option<String>,

        /// Service ID to match on
        #[arg(long)]
        service_id: Option<String>,

        /// Interface to match on
        #[arg(long)]
        interface: Option<String>,

        /// Confidence (0.0–1.0)
        #[arg(long)]
        confidence: Option<f32>,
    },
}

#[derive(Subcommand)]
enum ScrubberCommands {
    List,
    Arm {
        profile: String,
        #[arg(long)]
        revision: String,
    },
}
#[derive(Subcommand)]
enum DiversionCommands {
    List,
    Get {
        id: uuid::Uuid,
    },
    Preview {
        #[arg(long)]
        file: std::path::PathBuf,
    },
    Create {
        #[arg(long)]
        file: std::path::PathBuf,
        #[arg(long)]
        confirmation: String,
    },
    Withdraw {
        id: uuid::Uuid,
        /// Recorded with the first withdrawal request in the audit log
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum SpeakerCommands {
    /// List local FlowSpec rules only, not blackholes or router enforcement
    ListRoutes,
}

#[derive(Subcommand)]
enum OperatorCommands {
    /// Create a new operator (requires DATABASE_URL env var)
    Create {
        /// Username
        #[arg(short, long)]
        username: String,

        /// Password (omitting this option prompts without echo on a terminal)
        #[arg(short, long)]
        password: Option<String>,

        /// Role (admin, operator, or viewer)
        #[arg(short, long, default_value = "admin")]
        role: String,
    },

    /// List operators (requires DATABASE_URL env var)
    List,
}

#[derive(Subcommand)]
enum MitigationCommands {
    /// Preview a manual FlowSpec mitigation without changing routing state
    Preview {
        #[command(flatten)]
        rule: ManualMitigationArgs,
    },

    /// Create a manual FlowSpec mitigation after an admission preview
    Create {
        #[command(flatten)]
        rule: ManualMitigationArgs,
        /// Accept that a source-only rule affects every destination in the VRF
        #[arg(long, requires = "source_only")]
        confirm_destination_any: bool,
    },

    /// List mitigations, newest first, in every status unless --status is given
    List {
        /// Filter by status (pending, active, expired, withdrawn, rejected)
        #[arg(short, long)]
        status: Option<String>,

        /// Filter by customer ID
        #[arg(short, long)]
        customer: Option<String>,

        /// Max results
        #[arg(short, long, default_value = "50")]
        limit: u32,
    },

    /// Get mitigation details
    Get {
        /// Mitigation ID
        id: String,
    },

    /// Extend the remaining lifetime of an active enforced FlowSpec mitigation
    Extend {
        /// Mitigation ID
        id: uuid::Uuid,

        /// Requested remaining lifetime in seconds, subject to current policy
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        ttl_seconds: u32,

        /// Nonblank explanation, at most 1,024 UTF-8 bytes
        #[arg(short, long, value_parser = parse_extension_reason)]
        reason: String,
    },

    /// Withdraw a mitigation
    Withdraw {
        /// Mitigation ID
        id: String,

        /// Reason for withdrawal
        #[arg(short, long)]
        reason: String,

        /// Operator ID
        #[arg(short, long, env = "USER")]
        operator: String,
    },
}

#[derive(clap::Args)]
struct ManualMitigationArgs {
    /// Destination address or exact CIDR; omitted only with --source-only
    #[arg(required_unless_present = "source_only")]
    victim_ip: Option<String>,
    /// Configured routing scope; omitted or global uses global FlowSpec
    #[arg(long)]
    scope: Option<String>,
    /// Match a source CIDR and every destination in the selected VPN
    #[arg(long, requires_all = ["scope", "src_prefix"], conflicts_with_all = ["victim_ip", "dst_ports"])]
    source_only: bool,
    #[arg(long)]
    src_prefix: Option<String>,
    #[arg(long, default_value = "any", value_parser = ["any", "udp", "tcp", "icmp", "icmpv6"])]
    protocol: String,
    #[arg(long, value_delimiter = ',')]
    dst_ports: Vec<u16>,
    #[arg(long, default_value = "discard", value_parser = ["discard", "police"])]
    action: String,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    rate_bps: Option<u64>,
    /// Explicit requested lifetime, subject to current controller policy
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    ttl_seconds: u32,
    #[arg(short, long, value_parser = parse_extension_reason)]
    reason: String,
}

impl ManualMitigationArgs {
    fn vpn_scope(&self) -> Option<&str> {
        self.scope.as_deref().filter(|name| *name != "global")
    }

    fn request(&self, confirmed: bool) -> Result<(&'static str, serde_json::Value), String> {
        if (self.action == "police") != self.rate_bps.is_some() {
            return Err("--rate-bps is required for police and must be omitted for discard".into());
        }
        if self.source_only {
            let scope = self
                .vpn_scope()
                .ok_or("source-only rules require a VPN scope")?;
            let source = self
                .src_prefix
                .as_deref()
                .ok_or("--src-prefix is required")?;
            return Ok((
                "/v1/vpn/source-rules",
                serde_json::json!({
                    "scope": scope, "src_prefix": source, "protocol": self.protocol,
                    "action": self.action, "rate_bps": self.rate_bps,
                    "ttl_seconds": self.ttl_seconds, "reason": self.reason,
                    "confirm_destination_any": confirmed,
                }),
            ));
        }
        let victim = self.victim_ip.as_deref().ok_or("destination is required")?;
        let rule = serde_json::json!({
            "victim_ip": victim, "protocol": self.protocol, "src_prefix": self.src_prefix,
            "dst_ports": self.dst_ports, "action": self.action, "rate_bps": self.rate_bps,
            "ttl_seconds": self.ttl_seconds, "reason": self.reason,
        });
        Ok(match self.vpn_scope() {
            Some(scope) => (
                "/v1/vpn/mitigations",
                serde_json::json!({"scope": scope, "rule": rule}),
            ),
            None => ("/v1/mitigations", rule),
        })
    }
}

#[derive(Subcommand)]
enum SafelistCommands {
    /// List safelist entries
    List,

    /// Add prefix to safelist
    Add {
        /// Prefix (e.g., 10.0.0.0/8)
        prefix: String,

        /// Reason for safelisting
        #[arg(short, long)]
        reason: Option<String>,

        /// Operator ID
        #[arg(short, long, env = "USER")]
        operator: String,
    },

    /// Remove prefix from safelist
    Remove {
        /// Prefix to remove
        prefix: String,
    },
}

fn parse_extension_reason(value: &str) -> Result<String, String> {
    if value.trim().is_empty() || value.len() > 1024 {
        return Err("reason must contain text and be at most 1024 UTF-8 bytes".into());
    }
    Ok(value.to_owned())
}

// API Response types
#[derive(Debug, Deserialize, Serialize)]
struct HealthResponse {
    status: String,
    bgp_sessions: std::collections::HashMap<String, String>,
    active_mitigations: u32,
    database: String,
    gobgp: ComponentHealth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    speaker: Option<SpeakerHealth>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SpeakerHealth {
    backend: String,
    capabilities: prefixd::bgp::SpeakerCapabilities,
    #[serde(default)]
    daemon: Option<DaemonHealthObservation>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DaemonHealthObservation {
    status: String,
    version: Option<String>,
    uptime_seconds: Option<u64>,
    ready: Option<bool>,
    observed_at: Option<String>,
}

impl HealthResponse {
    fn require_peer_observation(&self) -> Result<(), String> {
        match self.gobgp.status.as_str() {
            "connected" => Ok(()),
            "unsupported" => Err("BGP peer observation is unsupported by this speaker".into()),
            _ => Err(format!(
                "BGP peer observation failed: {}",
                self.gobgp.error.as_deref().unwrap_or(&self.gobgp.status)
            )),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ComponentHealth {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct MitigationResponse {
    mitigation_id: String,
    status: String,
    customer_id: Option<String>,
    victim_ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dst_prefix: Option<String>,
    vector: String,
    action_type: String,
    rate_bps: Option<u64>,
    #[serde(default)]
    protocol: Option<u8>,
    #[serde(default)]
    dst_ports: Vec<u16>,
    #[serde(default)]
    src_prefix: Option<String>,
    /// ADR 028 match fields; absent from controllers that predate them.
    #[serde(default)]
    src_ports: Vec<u16>,
    #[serde(default)]
    fragment: Option<String>,
    #[serde(default)]
    packet_length: Option<PacketLength>,
    created_at: String,
    expires_at: String,
    scope_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vpn_scope: Option<prefixd::domain::VpnScopeSnapshot>,
    /// Present only for a blackhole, which drops all traffic to the victim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blackhole: Option<BlackholeRoute>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PacketLength {
    min: u16,
    max: u16,
}

impl MitigationResponse {
    fn destination_label(&self) -> &str {
        if self.vpn_scope.is_some() && self.dst_prefix.as_deref() == Some("") {
            "any"
        } else {
            &self.victim_ip
        }
    }

    /// One-line match, for example `udp src 123,389` or `udp non-first fragments`.
    fn match_summary(&self) -> String {
        if self.blackhole.is_some() || self.action_type == "blackhole" {
            return "all traffic".into();
        }
        let summary = match_summary(
            self.protocol,
            self.src_prefix.as_deref(),
            &self.dst_ports,
            &self.src_ports,
            self.fragment.as_deref(),
            self.packet_length
                .as_ref()
                .map(|length| (length.min, length.max)),
        );
        match &self.vpn_scope {
            Some(scope) => format!(
                "{summary}; {}",
                vpn_scope_summary(Some(&scope.identity), &scope.route_targets)
            ),
            None => summary,
        }
    }
}

fn vpn_scope_summary(
    identity: Option<&prefixd::domain::VpnFlowSpecIdentity>,
    route_targets: &[String],
) -> String {
    match identity {
        None => "global".into(),
        Some(identity) => format!(
            "VPN {} RD {} RT {}",
            match identity.family {
                prefixd::domain::VpnFlowSpecFamily::Ipv4 => "IPv4",
                prefixd::domain::VpnFlowSpecFamily::Ipv6 => "IPv6",
            },
            identity.rd(),
            route_targets.join(","),
        ),
    }
}

fn match_summary(
    protocol: Option<u8>,
    src_prefix: Option<&str>,
    dst_ports: &[u16],
    src_ports: &[u16],
    fragment: Option<&str>,
    packet_length: Option<(u16, u16)>,
) -> String {
    let join = |ports: &[u16]| {
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let mut parts = vec![match protocol {
        None => "any".to_string(),
        Some(1) => "icmp".into(),
        Some(6) => "tcp".into(),
        Some(17) => "udp".into(),
        Some(58) => "icmpv6".into(),
        Some(other) => other.to_string(),
    }];
    if let Some(prefix) = src_prefix {
        parts.push(format!("from {prefix}"));
    }
    if !src_ports.is_empty() {
        parts.push(format!("src {}", join(src_ports)));
    }
    if !dst_ports.is_empty() {
        parts.push(format!("dst {}", join(dst_ports)));
    }
    if let Some(fragment) = fragment {
        parts.push(match fragment {
            "non_first" => "non-first fragments".into(),
            other => format!("fragment {other}"),
        });
    }
    if let Some((min, max)) = packet_length {
        parts.push(format!("len {min}-{max}"));
    }
    parts.join(" ")
}

#[derive(Debug, Deserialize, Serialize)]
struct BlackholeRoute {
    next_hop: String,
    communities: Vec<String>,
    #[serde(default)]
    large_communities: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MitigationsListResponse {
    mitigations: Vec<MitigationResponse>,
    count: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExtendMitigationResponse {
    extended: bool,
    previous_expires_at: String,
    mitigation: MitigationResponse,
}

#[derive(Debug, Deserialize, Serialize)]
struct SafelistEntry {
    prefix: String,
    added_at: String,
    added_by: String,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

struct Client {
    base_url: String,
    token: Option<String>,
    http: reqwest::Client,
    session_cookie: Option<String>,
}

impl Client {
    fn new(base_url: String, token: Option<String>) -> Self {
        Self {
            base_url,
            token,
            http: reqwest::Client::new(),
            session_cookie: None,
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.request(method, &url);
        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        if let Some(cookie) = &self.session_cookie {
            req = req.header(reqwest::header::COOKIE, cookie);
        }
        req
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, String> {
        let resp = self
            .request(reqwest::Method::GET, path)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "unknown error".to_string(),
            });
            return Err(format!("{}: {}", status, err.error));
        }

        resp.json().await.map_err(|e| format!("parse error: {}", e))
    }

    async fn post<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, String> {
        let resp = self
            .request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "unknown error".to_string(),
            });
            return Err(format!("{}: {}", status, err.error));
        }

        resp.json().await.map_err(|e| format!("parse error: {}", e))
    }

    async fn post_empty(&self, path: &str, body: &impl Serialize) -> Result<(), String> {
        let resp = self
            .request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "unknown error".to_string(),
            });
            return Err(format!("{}: {}", status, err.error));
        }

        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<(), String> {
        let resp = self
            .request(reqwest::Method::DELETE, path)
            .send()
            .await
            .map_err(|e| format!("request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "unknown error".to_string(),
            });
            return Err(format!("{}: {}", status, err.error));
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut client = Client::new(cli.api, cli.token);
    client.session_cookie = cli.session_cookie;

    let result = match cli.command {
        Commands::Scrubbers(command) => cmd_scrubbers(&client, command).await,
        Commands::Diversions(command) => cmd_diversions(&client, command).await,
        Commands::Status => cmd_status(&client, cli.format).await,
        Commands::Mitigations(cmd) => cmd_mitigations(&client, cmd, cli.format).await,
        Commands::Safelist(cmd) => cmd_safelist(&client, cmd, cli.format).await,
        Commands::Operators(cmd) => cmd_operators(cmd, cli.format).await,
        Commands::Peers => cmd_peers(&client, cli.format).await,
        Commands::Speaker(SpeakerCommands::ListRoutes) => {
            cmd_speaker_routes(&client, cli.format).await
        }
        Commands::Reload => cmd_reload(&client, cli.format).await,
        Commands::Migrations => cmd_migrations(cli.format).await,
        Commands::SendCorroborator {
            source,
            vector,
            customer_id,
            pop,
            service_id,
            interface,
            confidence,
        } => {
            cmd_send_corroborator(
                &client,
                source,
                vector,
                customer_id,
                pop,
                service_id,
                interface,
                confidence,
                cli.format,
            )
            .await
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}

async fn cmd_scrubbers(client: &Client, command: ScrubberCommands) -> Result<(), String> {
    let value: serde_json::Value = match command {
        ScrubberCommands::List => client.get("/v1/scrubbers").await?,
        ScrubberCommands::Arm { profile, revision } => {
            if !profile
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            {
                return Err("invalid profile identifier".into());
            }
            client
                .post(
                    &format!("/v1/scrubbers/{profile}/arm"),
                    &serde_json::json!({"revision":revision}),
                )
                .await?
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn read_diversion_request(path: &std::path::Path) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(path).map_err(|_| "cannot read diversion request file")?;
    if bytes.len() > 16_384 {
        return Err("diversion request file is too large".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid diversion request JSON".into())
}

fn vpn_diversion_request(
    body: &serde_json::Value,
) -> Result<Option<prefixd::scrubber::api::VpnDiversionRequest>, String> {
    if body.get("diversion").is_some() || body["scope"].is_string() {
        let request: prefixd::scrubber::api::VpnDiversionRequest =
            serde_json::from_value(body.clone()).map_err(|_| "invalid VPN diversion envelope")?;
        if request.scope == "global"
            || request.scope.is_empty()
            || request.scope.len() > 64
            || !request
                .scope
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        {
            return Err("VPN diversion requires a configured VPN scope name".into());
        }
        return Ok(Some(request));
    }
    let request: prefixd::scrubber::api::CreateDiversion =
        serde_json::from_value(body.clone()).map_err(|_| "invalid diversion request")?;
    if request.scope.scope.is_some() {
        return Err("VPN diversion requires a named scope envelope".into());
    }
    Ok(None)
}

fn require_vpn_diversion_preview<'a>(
    request: &prefixd::scrubber::api::VpnDiversionRequest,
    preview: &'a serde_json::Value,
) -> Result<&'a str, String> {
    let candidate: prefixd::scrubber::Diversion =
        serde_json::from_value(preview["candidate"].clone())
            .map_err(|_| "controller did not acknowledge the VPN diversion; no rule was created")?;
    candidate
        .rule
        .validate()
        .map_err(|error| error.to_string())?;
    let identity = candidate
        .rule
        .nlri
        .scope
        .as_ref()
        .ok_or("controller did not acknowledge the VPN identity; no rule was created")?;
    prefixd::domain::VpnScopeSnapshot::new(
        &request.scope,
        identity.clone(),
        &candidate.rule.route_targets,
    )
    .map_err(|_| "controller did not acknowledge valid VPN route targets; no rule was created")?;
    if candidate.profile.scope != request.scope
        || candidate.profile.id != request.diversion.profile
        || request
            .diversion
            .scope
            .scope
            .as_ref()
            .is_some_and(|requested| requested != identity)
    {
        return Err(
            "controller acknowledged a different VPN profile or scope; no rule was created".into(),
        );
    }
    let mut expected = request.diversion.scope.clone();
    expected.scope = Some(identity.clone());
    if expected.compute_hash() != candidate.rule.nlri.compute_hash() {
        return Err("controller acknowledged a different VPN match; no rule was created".into());
    }
    let confirmation = preview["confirmation"]
        .as_str()
        .ok_or("controller did not provide a full diversion confirmation")?;
    let expected = prefixd::scrubber::ScrubberController::confirmation(&candidate)
        .map_err(|error| error.to_string())?;
    if confirmation != expected {
        return Err("controller confirmation does not match its VPN diversion".into());
    }
    Ok(confirmation)
}

async fn submit_diversion(
    client: &Client,
    mut body: serde_json::Value,
    confirmation: Option<&str>,
) -> Result<serde_json::Value, String> {
    if let Some(request) = vpn_diversion_request(&body)? {
        let preview: serde_json::Value = client.post("/v1/vpn/diversions/preview", &body).await?;
        let acknowledged = require_vpn_diversion_preview(&request, &preview)?;
        return match confirmation {
            None => Ok(preview),
            Some(confirmation) => {
                if confirmation != acknowledged {
                    return Err("diversion confirmation changed; preview and confirm the complete VPN rule again".into());
                }
                body["diversion"]["confirmation"] = confirmation.into();
                client.post("/v1/vpn/diversions", &body).await
            }
        };
    }
    match confirmation {
        None => client.post("/v1/diversions/preview", &body).await,
        Some(confirmation) => {
            body["confirmation"] = confirmation.into();
            client.post("/v1/diversions", &body).await
        }
    }
}

async fn cmd_diversions(client: &Client, command: DiversionCommands) -> Result<(), String> {
    let value: serde_json::Value = match command {
        DiversionCommands::List => client.get("/v1/diversions").await?,
        DiversionCommands::Get { id } => client.get(&format!("/v1/diversions/{id}")).await?,
        DiversionCommands::Withdraw { id, reason } => {
            let body = match reason {
                Some(reason) => serde_json::json!({ "reason": reason }),
                None => serde_json::json!({}),
            };
            client
                .post(&format!("/v1/diversions/{id}/withdraw"), &body)
                .await?
        }
        DiversionCommands::Preview { file } => {
            submit_diversion(client, read_diversion_request(&file)?, None).await?
        }
        DiversionCommands::Create { file, confirmation } => {
            submit_diversion(client, read_diversion_request(&file)?, Some(&confirmation)).await?
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?
    );
    Ok(())
}

async fn cmd_status(client: &Client, format: OutputFormat) -> Result<(), String> {
    let health: HealthResponse = client.get("/v1/health/detail").await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&health).unwrap());
        }
        OutputFormat::Table => {
            println!("Status: {}", health.status);
            println!("Active Mitigations: {}", health.active_mitigations);
            if let Some(speaker) = &health.speaker {
                println!("Speaker: {}", speaker.backend);
                match &speaker.daemon {
                    Some(daemon) if daemon.status == "observed" => {
                        println!(
                            "  Daemon version: {}",
                            daemon.version.as_deref().unwrap_or("unavailable")
                        );
                        println!(
                            "  Daemon uptime: {}",
                            daemon
                                .uptime_seconds
                                .map(|seconds| format!("{seconds}s"))
                                .unwrap_or_else(|| "unavailable".into())
                        );
                        println!(
                            "  Daemon ready: {}",
                            daemon
                                .ready
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "unavailable".into())
                        );
                        println!(
                            "  Observed at: {}",
                            daemon.observed_at.as_deref().unwrap_or("unavailable")
                        );
                    }
                    Some(daemon) => println!("  Daemon metadata: {}", daemon.status),
                    None => println!("  Daemon metadata: unavailable"),
                }
                if !speaker.capabilities.rule_reader {
                    println!("Rule observation: unsupported by this speaker");
                }
            }
            println!();
            println!("Components:");
            let db_indicator = if health.database == "connected" {
                "●"
            } else {
                "○"
            };
            println!("  {} Database: {}", db_indicator, health.database);
            let peer_indicator = if health.gobgp.status == "connected" {
                "●"
            } else {
                "○"
            };
            if let Some(ref err) = health.gobgp.error {
                println!(
                    "  {} Peer observation: {} ({})",
                    peer_indicator, health.gobgp.status, err
                );
            } else {
                println!(
                    "  {} Peer observation: {}",
                    peer_indicator, health.gobgp.status
                );
            }
            println!();
            println!("BGP Sessions:");
            if let Err(error) = health.require_peer_observation() {
                println!("  {error}");
            } else if health.bgp_sessions.is_empty() {
                println!("  (none configured)");
            } else {
                for (peer, state) in &health.bgp_sessions {
                    let indicator = if state == "established" { "●" } else { "○" };
                    println!("  {} {} - {}", indicator, peer, state);
                }
            }
        }
    }

    Ok(())
}

fn require_manual_preview(
    rule: &ManualMitigationArgs,
    preview: &serde_json::Value,
) -> Result<(), String> {
    if preview["outcome"] != "admissible" {
        return Err(format!(
            "admission preview refused: {}",
            preview["reason"].as_str().unwrap_or("unavailable")
        ));
    }
    if let Some(name) = rule.vpn_scope() {
        let scope: prefixd::domain::VpnScopeSnapshot =
            serde_json::from_value(preview["candidate"]["vpn_scope"].clone())
                .map_err(|_| "controller did not acknowledge the VPN scope; no rule was created")?;
        if scope.name != name {
            return Err(
                "controller acknowledged a different VPN scope; no rule was created".into(),
            );
        }
        let address = if rule.source_only {
            rule.src_prefix.as_deref()
        } else {
            rule.victim_ip.as_deref()
        }
        .and_then(|prefix| prefix.split('/').next())
        .ok_or("request has no address family")?
        .parse::<std::net::IpAddr>()
        .map_err(|_| "request address is invalid")?;
        if address.is_ipv4() != (scope.identity.family == prefixd::domain::VpnFlowSpecFamily::Ipv4)
        {
            return Err(
                "controller acknowledged a different VPN family; no rule was created".into(),
            );
        }
        if rule.source_only && preview["candidate"]["destination"] != "any" {
            return Err(
                "controller did not acknowledge destination:any; no rule was created".into(),
            );
        }
    }
    if let Some(source) = &rule.src_prefix {
        let requested =
            prefixd::domain::canonical_source_prefix(source).map_err(|e| e.to_string())?;
        if preview["candidate"]["scope"]["src_prefix"] != requested {
            return Err(
                "controller did not acknowledge the source prefix; no rule was created".into(),
            );
        }
    }
    Ok(())
}

async fn cmd_manual_mitigation(
    client: &Client,
    rule: ManualMitigationArgs,
    create: bool,
    confirmed: bool,
) -> Result<(), String> {
    if create && rule.source_only && !confirmed {
        return Err("source-only creation requires --confirm-destination-any".into());
    }
    let (path, body) = rule.request(confirmed)?;
    let preview: serde_json::Value = client.post(&format!("{path}/preview"), &body).await?;
    let value = if create {
        require_manual_preview(&rule, &preview)?;
        client.post(path, &body).await?
    } else {
        preview
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?
    );
    Ok(())
}

async fn cmd_mitigations(
    client: &Client,
    cmd: MitigationCommands,
    format: OutputFormat,
) -> Result<(), String> {
    match cmd {
        MitigationCommands::Preview { rule } => {
            cmd_manual_mitigation(client, rule, false, false).await?;
        }
        MitigationCommands::Create {
            rule,
            confirm_destination_any,
        } => {
            cmd_manual_mitigation(client, rule, true, confirm_destination_any).await?;
        }
        MitigationCommands::List {
            status,
            customer,
            limit,
        } => {
            let mut path = format!("/v1/mitigations?limit={}", limit);
            if let Some(s) = status {
                path.push_str(&format!("&status={}", s));
            }
            if let Some(c) = customer {
                path.push_str(&format!("&customer_id={}", c));
            }

            let resp: MitigationsListResponse = client.get(&path).await?;

            match format {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&resp.mitigations).unwrap()
                    );
                }
                OutputFormat::Table => {
                    if resp.mitigations.is_empty() {
                        println!("No mitigations found.");
                        return Ok(());
                    }

                    println!(
                        "{:<36}  {:<10}  {:<15}  {:<10}  {:<9}  {:<19}  MATCH",
                        "ID", "STATUS", "VICTIM_IP", "VECTOR", "ACTION", "EXPIRES"
                    );
                    println!("{}", "-".repeat(120));

                    for m in &resp.mitigations {
                        let expires = &m.expires_at[..19]; // Trim to datetime
                        println!(
                            "{:<36}  {:<10}  {:<15}  {:<10}  {:<9}  {:<19}  {}",
                            m.mitigation_id,
                            m.status,
                            m.destination_label(),
                            m.vector,
                            m.action_type,
                            expires,
                            m.match_summary()
                        );
                    }

                    println!();
                    println!("Count: {}", resp.count);
                }
            }
        }

        MitigationCommands::Get { id } => {
            let path = format!("/v1/mitigations/{}", id);
            let m: MitigationResponse = client.get(&path).await?;

            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&m).unwrap());
                }
                OutputFormat::Table => {
                    println!("Mitigation ID:  {}", m.mitigation_id);
                    println!("Status:         {}", m.status);
                    println!("Victim IP:      {}", m.destination_label());
                    println!("Vector:         {}", m.vector);
                    println!("Action:         {}", m.action_type);
                    println!("Match:          {}", m.match_summary());
                    println!(
                        "Scope:          {}",
                        vpn_scope_summary(
                            m.vpn_scope.as_ref().map(|scope| &scope.identity),
                            m.vpn_scope
                                .as_ref()
                                .map_or(&[], |scope| scope.route_targets.as_slice())
                        )
                    );
                    if let Some(rate) = m.rate_bps {
                        println!("Rate (bps):     {}", rate);
                    }
                    if let Some(route) = &m.blackhole {
                        println!("Blackhole:      drops all traffic to the victim");
                        println!("Next hop:       {}", route.next_hop);
                        println!("Communities:    {}", route.communities.join(" "));
                        if !route.large_communities.is_empty() {
                            println!("Large comms:    {}", route.large_communities.join(" "));
                        }
                    }
                    println!(
                        "Customer:       {}",
                        m.customer_id.as_deref().unwrap_or("N/A")
                    );
                    println!("Created:        {}", m.created_at);
                    println!("Expires:        {}", m.expires_at);
                    println!("Scope Hash:     {}", m.scope_hash);
                }
            }
        }

        MitigationCommands::Extend {
            id,
            ttl_seconds,
            reason,
        } => {
            let path = format!("/v1/mitigations/{id}/extend");
            let body = serde_json::json!({ "ttl_seconds": ttl_seconds, "reason": reason });
            let response: ExtendMitigationResponse = client.post(&path, &body).await?;
            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&response).unwrap());
                }
                OutputFormat::Table => {
                    println!("Mitigation ID:  {}", response.mitigation.mitigation_id);
                    println!(
                        "Lifetime:       {}",
                        if response.extended {
                            "extended"
                        } else {
                            "unchanged"
                        }
                    );
                    println!("Previous expiry: {}", response.previous_expires_at);
                    println!("Saved expiry:    {}", response.mitigation.expires_at);
                }
            }
        }

        MitigationCommands::Withdraw {
            id,
            reason,
            operator,
        } => {
            let path = format!("/v1/mitigations/{}/withdraw", id);
            let body = serde_json::json!({
                "operator_id": operator,
                "reason": reason
            });

            let m: MitigationResponse = client.post(&path, &body).await?;
            println!("Withdrawn mitigation {}", m.mitigation_id);
        }
    }

    Ok(())
}

async fn cmd_safelist(
    client: &Client,
    cmd: SafelistCommands,
    format: OutputFormat,
) -> Result<(), String> {
    match cmd {
        SafelistCommands::List => {
            let entries: Vec<SafelistEntry> = client.get("/v1/safelist").await?;

            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&entries).unwrap());
                }
                OutputFormat::Table => {
                    if entries.is_empty() {
                        println!("Safelist is empty.");
                        return Ok(());
                    }

                    println!(
                        "{:<20}  {:<15}  {:<20}  REASON",
                        "PREFIX", "ADDED_BY", "ADDED_AT"
                    );
                    println!("{}", "-".repeat(80));

                    for e in &entries {
                        let added = &e.added_at[..19];
                        println!(
                            "{:<20}  {:<15}  {:<20}  {}",
                            e.prefix,
                            e.added_by,
                            added,
                            e.reason.as_deref().unwrap_or("")
                        );
                    }
                }
            }
        }

        SafelistCommands::Add {
            prefix,
            reason,
            operator,
        } => {
            let body = serde_json::json!({
                "operator_id": operator,
                "prefix": prefix,
                "reason": reason
            });

            client.post_empty("/v1/safelist", &body).await?;
            println!("Added {} to safelist", prefix);
        }

        SafelistCommands::Remove { prefix } => {
            let path = format!("/v1/safelist/{}", urlencoding::encode(&prefix));
            client.delete(&path).await?;
            println!("Removed {} from safelist", prefix);
        }
    }

    Ok(())
}

async fn cmd_peers(client: &Client, format: OutputFormat) -> Result<(), String> {
    let health: HealthResponse = client.get("/v1/health/detail").await?;
    health.require_peer_observation()?;

    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&health.bgp_sessions).unwrap()
            );
        }
        OutputFormat::Table => {
            if health.bgp_sessions.is_empty() {
                println!("No BGP peers configured.");
                return Ok(());
            }

            println!("{:<30}  {:<15}", "PEER", "STATE");
            println!("{}", "-".repeat(50));

            for (peer, state) in &health.bgp_sessions {
                println!("{:<30}  {:<15}", peer, state);
            }
        }
    }

    Ok(())
}

async fn cmd_speaker_routes(client: &Client, format: OutputFormat) -> Result<(), String> {
    use prefixd::api::handlers::{FlowSpecObservationScope, SpeakerRoutesResponse};

    let inventory: SpeakerRoutesResponse = client.get("/v1/speaker/routes").await?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&inventory).unwrap()),
        OutputFormat::Table => {
            let scope = match inventory.observation_scope {
                FlowSpecObservationScope::RetainedLocalFlowSpecIntent => {
                    "retained local FlowSpec intent"
                }
                FlowSpecObservationScope::AcceptedLocalFlowSpecRib => "accepted local FlowSpec RIB",
                FlowSpecObservationScope::AdapterLocalFlowSpec => {
                    "adapter local FlowSpec read-back"
                }
            };
            println!("Speaker: {}", inventory.backend);
            println!("Observation: {scope}");
            println!("Local FlowSpec rules only; no router enforcement proof.");
            if inventory.routes.is_empty() {
                println!("No local FlowSpec rules observed.");
                return Ok(());
            }
            println!(
                "{:<25}  {:<45}  {:<20}  {:<40}  OWNER",
                "DESTINATION", "MATCH", "ACTION", "SCOPE"
            );
            for rule in inventory.routes {
                let nlri = &rule.nlri;
                let summary = match_summary(
                    nlri.protocol,
                    nlri.src_prefix.as_deref(),
                    &nlri.dst_ports,
                    &nlri.src_ports,
                    nlri.fragment.map(|fragment| match fragment {
                        prefixd::domain::FragmentMatch::NonFirst => "non_first",
                    }),
                    nlri.packet_length.map(|length| (length.min, length.max)),
                );
                let actions = rule
                    .actions
                    .iter()
                    .map(|action| match action.rate_bps {
                        Some(rate) => format!("{} {rate} bps", action.action_type),
                        None => action.action_type.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "{:<25}  {:<45}  {:<20}  {:<40}  {}",
                    if nlri.dst_prefix.is_empty() {
                        "any"
                    } else {
                        &nlri.dst_prefix
                    },
                    summary,
                    actions,
                    vpn_scope_summary(nlri.scope.as_ref(), &rule.route_targets),
                    if rule.owner.is_empty() {
                        "-"
                    } else {
                        &rule.owner
                    }
                );
            }
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
struct ReloadResponse {
    reloaded: Vec<String>,
    timestamp: String,
}

async fn cmd_reload(client: &Client, format: OutputFormat) -> Result<(), String> {
    let resp: ReloadResponse = client
        .post("/v1/config/reload", &serde_json::json!({}))
        .await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&resp).unwrap());
        }
        OutputFormat::Table => {
            println!("Reloaded: {}", resp.reloaded.join(", "));
            println!("Timestamp: {}", resp.timestamp);
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
struct CorroboratorResponse {
    signal_id: String,
    status: String,
    attached_group_ids: Vec<String>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "Pass the corroborator subcommand's independent flags directly to its request builder"
)]
async fn cmd_send_corroborator(
    client: &Client,
    source: String,
    vector: Option<String>,
    customer_id: Option<String>,
    pop: Option<String>,
    service_id: Option<String>,
    interface: Option<String>,
    confidence: Option<f32>,
    format: OutputFormat,
) -> Result<(), String> {
    if customer_id.is_none() && pop.is_none() && service_id.is_none() && interface.is_none() {
        return Err(
            "at least one of --customer-id, --pop, --service-id, --interface is required"
                .to_string(),
        );
    }

    let mut body = serde_json::Map::new();
    body.insert("source".to_string(), serde_json::json!(source));
    if let Some(v) = vector {
        body.insert("vector".to_string(), serde_json::json!(v));
    }
    if let Some(v) = customer_id {
        body.insert("customer_id".to_string(), serde_json::json!(v));
    }
    if let Some(v) = pop {
        body.insert("pop".to_string(), serde_json::json!(v));
    }
    if let Some(v) = service_id {
        body.insert("service_id".to_string(), serde_json::json!(v));
    }
    if let Some(v) = interface {
        body.insert("interface".to_string(), serde_json::json!(v));
    }
    if let Some(v) = confidence {
        body.insert("confidence".to_string(), serde_json::json!(v));
    }

    let resp: CorroboratorResponse = client
        .post("/v1/signals/corroborator", &serde_json::Value::Object(body))
        .await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&resp).unwrap());
        }
        OutputFormat::Table => {
            println!("signal_id:          {}", resp.signal_id);
            println!("status:             {}", resp.status);
            println!(
                "attached_groups:    {}",
                if resp.attached_group_ids.is_empty() {
                    "(none - cached)".to_string()
                } else {
                    resp.attached_group_ids.join(", ")
                }
            );
        }
    }
    Ok(())
}

async fn cmd_operators(cmd: OperatorCommands, format: OutputFormat) -> Result<(), String> {
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL environment variable not set")?;

    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .map_err(|e| format!("failed to connect to database: {}", e))?;

    match cmd {
        OperatorCommands::Create {
            username,
            password,
            role,
        } => {
            // Validate role
            let role_lower = role.to_lowercase();
            if role_lower != "admin" && role_lower != "operator" && role_lower != "viewer" {
                return Err("role must be 'admin', 'operator', or 'viewer'".to_string());
            }

            // Get password (prompt if not provided)
            let password = match password {
                Some(p) => p,
                None => inquire::Password::new("Password:")
                    .without_confirmation()
                    .prompt()
                    .map_err(|e| format!("failed to read password: {}", e))?
                    .trim()
                    .to_string(),
            };

            if password.is_empty() {
                return Err("password cannot be empty".to_string());
            }

            // Hash password with argon2
            let argon2 = Argon2::default();
            let password_hash = argon2
                .hash_password(password.as_bytes())
                .map_err(|e| format!("failed to hash password: {}", e))?
                .to_string();

            // Check if username exists
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operators WHERE username = $1)")
                    .bind(&username)
                    .fetch_one(&pool)
                    .await
                    .map_err(|e| format!("database error: {}", e))?;

            if exists {
                return Err(format!("operator '{}' already exists", username));
            }

            // Insert operator
            let id: uuid::Uuid = sqlx::query_scalar(
                r#"
                INSERT INTO operators (username, password_hash, role)
                VALUES ($1, $2, $3)
                RETURNING operator_id
                "#,
            )
            .bind(&username)
            .bind(&password_hash)
            .bind(&role_lower)
            .fetch_one(&pool)
            .await
            .map_err(|e| format!("failed to create operator: {}", e))?;

            match format {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "id": id.to_string(),
                            "username": username,
                            "role": role_lower
                        })
                    );
                }
                OutputFormat::Table => {
                    println!(
                        "Created operator '{}' (id: {}, role: {})",
                        username, id, role_lower
                    );
                }
            }
        }

        OperatorCommands::List => {
            #[derive(sqlx::FromRow, Serialize)]
            struct OperatorRow {
                id: uuid::Uuid,
                username: String,
                role: String,
                #[sqlx(try_from = "prefixd::db::CheckedTimestamp")]
                created_at: chrono::DateTime<chrono::Utc>,
                #[sqlx(try_from = "prefixd::db::CheckedTimestamp")]
                last_login: Option<chrono::DateTime<chrono::Utc>>,
            }

            let operators: Vec<OperatorRow> = sqlx::query_as(
                "SELECT operator_id AS id, username, role, created_at, last_login_at AS last_login FROM operators ORDER BY created_at"
            )
            .fetch_all(&pool)
            .await
            .map_err(|e| format!("database error: {}", e))?;

            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&operators).unwrap());
                }
                OutputFormat::Table => {
                    if operators.is_empty() {
                        println!("No operators found.");
                        return Ok(());
                    }

                    println!(
                        "{:<36}  {:<20}  {:<8}  {:<20}  LAST LOGIN",
                        "ID", "USERNAME", "ROLE", "CREATED"
                    );
                    println!("{}", "-".repeat(110));

                    for op in &operators {
                        let created = op.created_at.format("%Y-%m-%d %H:%M:%S").to_string();
                        let last_login = op
                            .last_login
                            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| "never".to_string());
                        println!(
                            "{:<36}  {:<20}  {:<8}  {:<20}  {}",
                            op.id, op.username, op.role, created, last_login
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

async fn cmd_migrations(format: OutputFormat) -> Result<(), String> {
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL environment variable not set")?;

    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .map_err(|e| format!("failed to connect to database: {}", e))?;

    #[derive(sqlx::FromRow, Serialize)]
    struct MigrationRow {
        version: i32,
        name: String,
        #[sqlx(try_from = "prefixd::db::CheckedTimestamp")]
        applied_at: chrono::DateTime<chrono::Utc>,
    }

    let has_table: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'schema_migrations')",
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| format!("database error: {}", e))?;

    if !has_table {
        println!("No schema_migrations table found. Run prefixd to initialize.");
        return Ok(());
    }

    let rows: Vec<MigrationRow> =
        sqlx::query_as("SELECT version, name, applied_at FROM schema_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .map_err(|e| format!("database error: {}", e))?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&rows).unwrap());
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("No migrations applied.");
                return Ok(());
            }

            println!("{:<8}  {:<30}  APPLIED AT", "VERSION", "NAME");
            println!("{}", "-".repeat(65));

            for m in &rows {
                let applied = m.applied_at.format("%Y-%m-%d %H:%M:%S").to_string();
                println!("{:<8}  {:<30}  {}", m.version, m.name, applied);
            }

            println!();
            println!("{} migration(s) applied", rows.len());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diversion_cli_fixture(family: &str) -> (serde_json::Value, serde_json::Value) {
        let (prefix, target) = if family == "ipv4" {
            ("203.0.113.10/32", "192.0.2.99")
        } else {
            ("2001:db8:1::10/128", "2001:db8::99")
        };
        let request = serde_json::json!({"scope":"TRANSIT","diversion":{
            "profile":"a","scope":{"dst_prefix":prefix,"protocol":6,"dst_ports":[443]},
            "ttl_seconds":60,"reason":"confirmed attack"
        }});
        let candidate: prefixd::scrubber::Diversion = serde_json::from_value(serde_json::json!({
            "id":"7f72a903-63d1-4a4a-a5db-0517e0a7df1d",
            "controller_incarnation":"7f72a903-63d1-4a4a-a5db-0517e0a7df1e",
            "controller_epoch":1,"pop":"p","customer_id":"c",
            "profile":{"id":"a","revision":"r1","scope":"TRANSIT","router_peers":[],
                "policy_binding":"vpn","qualification_receipt":"pilot","destinations":[prefix]},
            "rule":{"nlri":{"dst_prefix":prefix,"protocol":6,"dst_ports":[443],
                "scope":{"family":family,"rd":"44407:40"}},
                "target":target,"route_targets":["44407:777"],"owner":"prefixd.scrub.cli","revision":7},
            "created_at":"2026-11-08T00:00:00Z","expires_at":"2026-11-08T00:01:00Z",
            "actor":"operator","reason":"confirmed attack","dry_run":true,"status":"pending",
            "withdrawal_reason":null,"windows":[],"generation":null,"last_error":null
        })).unwrap();
        let confirmation = prefixd::scrubber::ScrubberController::confirmation(&candidate).unwrap();
        (
            request,
            serde_json::json!({"candidate":candidate,"confirmation":confirmation}),
        )
    }

    #[test]
    fn diversion_envelopes_and_scope_acknowledgements_fail_closed() {
        for family in ["ipv4", "ipv6"] {
            let (body, preview) = diversion_cli_fixture(family);
            let request = vpn_diversion_request(&body).unwrap().unwrap();
            assert_eq!(
                require_vpn_diversion_preview(&request, &preview).unwrap(),
                preview["confirmation"].as_str().unwrap()
            );
            assert!(vpn_diversion_request(&body["diversion"]).unwrap().is_none());
            for pointer in [
                "/candidate/rule/nlri/scope",
                "/candidate/rule/route_targets",
                "/candidate/profile/scope",
                "/confirmation",
            ] {
                let mut missing = preview.clone();
                *missing.pointer_mut(pointer).unwrap() = serde_json::Value::Null;
                assert!(
                    require_vpn_diversion_preview(&request, &missing).is_err(),
                    "{pointer}"
                );
            }
            for (pointer, value) in [
                (
                    "/candidate/rule/nlri/scope/rd",
                    serde_json::json!("44407:41"),
                ),
                (
                    "/candidate/rule/nlri/scope/family",
                    serde_json::json!(if family == "ipv4" { "ipv6" } else { "ipv4" }),
                ),
                (
                    "/candidate/rule/route_targets",
                    serde_json::json!(["44407:778"]),
                ),
                ("/candidate/profile/scope", serde_json::json!("OTHER")),
                ("/candidate/rule/nlri/protocol", serde_json::json!(17)),
            ] {
                let mut changed = preview.clone();
                *changed.pointer_mut(pointer).unwrap() = value;
                assert!(
                    require_vpn_diversion_preview(&request, &changed).is_err(),
                    "{pointer}"
                );
            }
            for malformed in [
                serde_json::json!({"scope":"global","diversion":body["diversion"]}),
                serde_json::json!({"scope":"bad scope","diversion":body["diversion"]}),
                serde_json::json!({"diversion":body["diversion"]}),
                serde_json::json!({"scope":"TRANSIT"}),
                serde_json::json!({"scope":"TRANSIT","diversion":body["diversion"],"confirmation":"wrong level"}),
                serde_json::json!({"profile":"a","scope":preview["candidate"]["rule"]["nlri"],"ttl_seconds":60,"reason":"test"}),
            ] {
                assert!(vpn_diversion_request(&malformed).is_err(), "{malformed}");
            }
        }
    }

    #[tokio::test]
    async fn diversion_cli_uses_scoped_preview_and_nested_confirmation_without_changing_global_files()
     {
        use std::sync::{Arc, Mutex};
        for family in ["ipv4", "ipv6", "global"] {
            let (mut body, preview) =
                diversion_cli_fixture(if family == "global" { "ipv4" } else { family });
            if family == "global" {
                body = body["diversion"].clone();
            }
            let confirmation = preview["confirmation"].as_str().unwrap().to_string();
            let received = Arc::new(Mutex::new(Vec::new()));
            let requests = received.clone();
            let app = axum::Router::new().fallback(
                move |uri: axum::http::Uri, axum::Json(body): axum::Json<serde_json::Value>| {
                    let requests = requests.clone();
                    let preview = preview.clone();
                    async move {
                        requests
                            .lock()
                            .unwrap()
                            .push((uri.path().to_string(), body));
                        axum::Json(if uri.path().ends_with("/preview") {
                            preview
                        } else {
                            serde_json::json!({"created":true})
                        })
                    }
                },
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = Client::new(format!("http://{}", listener.local_addr().unwrap()), None);
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let result = submit_diversion(&client, body, Some(&confirmation)).await;
            server.abort();
            let _ = server.await;
            assert_eq!(result.unwrap()["created"], true);
            let requests = received.lock().unwrap();
            if family == "global" {
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0].0, "/v1/diversions");
                assert_eq!(requests[0].1["confirmation"], confirmation);
            } else {
                assert_eq!(
                    requests
                        .iter()
                        .map(|(path, _)| path.as_str())
                        .collect::<Vec<_>>(),
                    ["/v1/vpn/diversions/preview", "/v1/vpn/diversions"]
                );
                assert_eq!(requests[1].1["diversion"]["confirmation"], confirmation);
                assert!(requests[1].1.get("confirmation").is_none());
            }
        }
    }

    #[tokio::test]
    async fn diversion_cli_refuses_missing_acknowledgements_changed_confirmation_and_http_errors() {
        use std::sync::{Arc, Mutex};
        for failure in ["missing_ack", "changed_confirmation", "http_error"] {
            let (body, mut preview) = diversion_cli_fixture("ipv4");
            let mut confirmation = preview["confirmation"].as_str().unwrap().to_string();
            if failure == "missing_ack" {
                preview["candidate"] = serde_json::json!({});
            }
            if failure == "changed_confirmation" {
                confirmation.push_str(" stale");
            }
            let received = Arc::new(Mutex::new(Vec::new()));
            let requests = received.clone();
            let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
                let requests = requests.clone();
                let preview = preview.clone();
                async move {
                    requests.lock().unwrap().push(uri.path().to_string());
                    let status = if failure == "http_error" {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        axum::http::StatusCode::OK
                    };
                    (status, axum::Json(preview))
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = Client::new(format!("http://{}", listener.local_addr().unwrap()), None);
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let result = submit_diversion(&client, body, Some(&confirmation)).await;
            server.abort();
            let _ = server.await;
            assert!(result.is_err(), "{failure}");
            assert_eq!(*received.lock().unwrap(), ["/v1/vpn/diversions/preview"]);
        }
    }

    #[tokio::test]
    async fn diversion_cli_transport_failure_never_retries_through_global() {
        use tokio::io::AsyncReadExt;
        let (body, preview) = diversion_cli_fixture("ipv6");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = Client::new(format!("http://{}", listener.local_addr().unwrap()), None);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let read = stream.read(&mut bytes).await.unwrap();
            String::from_utf8_lossy(&bytes[..read]).to_string()
        });
        let result = submit_diversion(&client, body, preview["confirmation"].as_str()).await;
        let request = server.await.unwrap();
        assert!(result.unwrap_err().contains("request failed"));
        assert!(request.starts_with("POST /v1/vpn/diversions/preview "));
    }

    fn manual_args(extra: &[&str]) -> ManualMitigationArgs {
        let cli = Cli::try_parse_from(
            ["prefixdctl", "mitigations", "preview"]
                .into_iter()
                .chain(extra.iter().copied()),
        )
        .unwrap();
        match cli.command {
            Commands::Mitigations(MitigationCommands::Preview { rule }) => rule,
            _ => unreachable!(),
        }
    }

    fn vpn_preview(family: &str) -> serde_json::Value {
        serde_json::json!({
            "outcome": "admissible",
            "candidate": {
                "vpn_scope": {"name": "TRANSIT", "identity": {"family": family, "rd": "44407:40"}, "route_targets": ["44407:777"]},
                "destination": "any",
                "scope": {"src_prefix": if family == "ipv4" {"198.51.100.0/24"} else {"2001:db8:2::/64"}},
            }
        })
    }

    #[test]
    fn manual_cli_scoped_request_shapes_and_source_only_constraints() {
        let normal = manual_args(&["192.0.2.1", "--ttl-seconds", "60", "--reason", "test"]);
        let (path, body) = normal.request(false).unwrap();
        assert_eq!(path, "/v1/mitigations");
        assert_eq!(body["victim_ip"], "192.0.2.1");
        assert!(body.get("scope").is_none());
        let scoped = manual_args(&[
            "192.0.2.1",
            "--scope",
            "TRANSIT",
            "--ttl-seconds",
            "60",
            "--reason",
            "test",
        ]);
        let (path, body) = scoped.request(false).unwrap();
        assert_eq!(path, "/v1/vpn/mitigations");
        assert_eq!(body["scope"], "TRANSIT");
        assert_eq!(body["rule"]["victim_ip"], "192.0.2.1");
        for source in ["198.51.100.0/24", "2001:db8:2::/64"] {
            let rule = manual_args(&[
                "--source-only",
                "--scope",
                "TRANSIT",
                "--src-prefix",
                source,
                "--ttl-seconds",
                "30",
                "--reason",
                "test",
            ]);
            let (path, body) = rule.request(true).unwrap();
            assert_eq!(path, "/v1/vpn/source-rules");
            assert_eq!(body["src_prefix"], source);
            assert_eq!(body["confirm_destination_any"], true);
            assert!(body.get("victim_ip").is_none());
            assert!(body.get("dst_prefix").is_none());
        }
        for invalid in [
            vec![
                "--source-only",
                "--scope",
                "TRANSIT",
                "--ttl-seconds",
                "30",
                "--reason",
                "test",
            ],
            vec![
                "--source-only",
                "--src-prefix",
                "198.51.100.0/24",
                "--ttl-seconds",
                "30",
                "--reason",
                "test",
            ],
            vec![
                "--source-only",
                "--scope",
                "TRANSIT",
                "--src-prefix",
                "198.51.100.0/24",
                "--reason",
                "test",
            ],
            vec![
                "192.0.2.1",
                "--source-only",
                "--scope",
                "TRANSIT",
                "--src-prefix",
                "198.51.100.0/24",
                "--ttl-seconds",
                "30",
                "--reason",
                "test",
            ],
            vec![
                "--source-only",
                "--scope",
                "TRANSIT",
                "--src-prefix",
                "198.51.100.0/24",
                "--action",
                "marking",
                "--ttl-seconds",
                "30",
                "--reason",
                "test",
            ],
        ] {
            assert!(
                Cli::try_parse_from(
                    ["prefixdctl", "mitigations", "preview"]
                        .into_iter()
                        .chain(invalid)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn scoped_preview_must_acknowledge_scope_family_source_and_any_destination() {
        let rule = manual_args(&[
            "--source-only",
            "--scope",
            "TRANSIT",
            "--src-prefix",
            "198.51.100.1/24",
            "--ttl-seconds",
            "30",
            "--reason",
            "test",
        ]);
        let valid = vpn_preview("ipv4");
        assert!(require_manual_preview(&rule, &valid).is_ok());
        for pointer in [
            "/candidate/vpn_scope",
            "/candidate/vpn_scope/identity/rd",
            "/candidate/vpn_scope/route_targets",
            "/candidate/destination",
            "/candidate/scope/src_prefix",
        ] {
            let mut bad = valid.clone();
            *bad.pointer_mut(pointer).unwrap() = serde_json::Value::Null;
            assert!(require_manual_preview(&rule, &bad).is_err(), "{pointer}");
        }
        let mut wrong_name = valid.clone();
        wrong_name["candidate"]["vpn_scope"]["name"] = "OTHER".into();
        assert!(require_manual_preview(&rule, &wrong_name).is_err());
        assert!(require_manual_preview(&rule, &vpn_preview("ipv6")).is_err());
        let ipv6 = manual_args(&[
            "--source-only",
            "--scope",
            "TRANSIT",
            "--src-prefix",
            "2001:db8:2::/64",
            "--ttl-seconds",
            "30",
            "--reason",
            "test",
        ]);
        assert!(require_manual_preview(&ipv6, &vpn_preview("ipv6")).is_ok());
    }

    #[test]
    fn vpn_output_keeps_scope_and_destination_any_distinct() {
        for family in ["ipv4", "ipv6"] {
            let snapshot: prefixd::domain::VpnScopeSnapshot =
                serde_json::from_value(vpn_preview(family)["candidate"]["vpn_scope"].clone())
                    .unwrap();
            let summary = vpn_scope_summary(Some(&snapshot.identity), &snapshot.route_targets);
            assert!(summary.contains(if family == "ipv4" { "IPv4" } else { "IPv6" }));
            assert!(summary.contains("RD 44407:40 RT 44407:777"));
            let mitigation: MitigationResponse = serde_json::from_value(serde_json::json!({
                "mitigation_id": "m", "status": "active", "customer_id": null,
                "victim_ip": "", "dst_prefix": "", "vector": "manual",
                "action_type": "discard", "rate_bps": null, "created_at": "",
                "expires_at": "", "scope_hash": "s", "vpn_scope": snapshot,
            }))
            .unwrap();
            assert_eq!(mitigation.destination_label(), "any");
            assert!(mitigation.match_summary().contains(&summary));
        }
        assert_eq!(vpn_scope_summary(None, &[]), "global");
    }

    #[tokio::test]
    async fn old_controller_acknowledgement_never_causes_unscoped_retry_or_creation() {
        use std::sync::{Arc, Mutex};
        let paths = Arc::new(Mutex::new(Vec::new()));
        let received = paths.clone();
        let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
            let received = received.clone();
            async move {
                received.lock().unwrap().push(uri.path().to_string());
                axum::Json(serde_json::json!({"outcome":"admissible", "candidate":{}}))
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = Client::new(format!("http://{}", listener.local_addr().unwrap()), None);
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let rule = manual_args(&[
            "192.0.2.1",
            "--scope",
            "TRANSIT",
            "--ttl-seconds",
            "60",
            "--reason",
            "test",
        ]);
        let result = cmd_manual_mitigation(&client, rule, true, false).await;
        server.abort();
        let _ = server.await;
        assert!(result.unwrap_err().contains("did not acknowledge"));
        assert_eq!(*paths.lock().unwrap(), ["/v1/vpn/mitigations/preview"]);
    }

    #[test]
    fn extension_requires_positive_ttl_and_a_bounded_reason() {
        let args = [
            "prefixdctl",
            "mitigations",
            "extend",
            "7f72a903-63d1-4a4a-a5db-0517e0a7df1d",
        ];
        let parse =
            |extra: &[&str]| Cli::try_parse_from(args.iter().copied().chain(extra.iter().copied()));
        let cli = parse(&["--ttl-seconds", "600", "--reason", "attack continues"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Mitigations(MitigationCommands::Extend { ttl_seconds: 600, reason, .. })
                if reason == "attack continues"
        ));
        for invalid in [
            vec!["--ttl-seconds", "0", "--reason", "attack continues"],
            vec!["--ttl-seconds", "-1", "--reason", "attack continues"],
            vec![
                "--ttl-seconds",
                "4294967296",
                "--reason",
                "attack continues",
            ],
            vec!["--ttl-seconds", "600"],
            vec!["--reason", "attack continues"],
            vec!["--ttl-seconds", "600", "--reason", " \t\n"],
            vec![
                "--ttl-seconds",
                "600",
                "--reason",
                "test",
                "--operator",
                "forged",
            ],
        ] {
            assert!(parse(&invalid).is_err(), "{invalid:?}");
        }
        assert!(parse_extension_reason(&"é".repeat(512)).is_ok());
        assert!(parse_extension_reason(&"é".repeat(513)).is_err());
    }

    #[test]
    fn mitigation_match_summary_shows_amplification_fields() {
        let base = serde_json::json!({
            "mitigation_id": "m", "status": "active", "customer_id": null,
            "victim_ip": "203.0.113.10", "vector": "udp_amplification",
            "action_type": "discard", "rate_bps": null, "created_at": "",
            "expires_at": "", "scope_hash": "s"
        });
        let summary = |extra: serde_json::Value| {
            let mut value = base.clone();
            for (key, field) in extra.as_object().unwrap() {
                value[key] = field.clone();
            }
            serde_json::from_value::<MitigationResponse>(value)
                .unwrap()
                .match_summary()
        };
        // An older controller sends none of the match fields.
        assert_eq!(summary(serde_json::json!({})), "any");
        assert_eq!(
            summary(serde_json::json!({ "protocol": 6, "src_prefix": "198.51.100.0/24" })),
            "tcp from 198.51.100.0/24"
        );
        assert_eq!(
            summary(
                serde_json::json!({ "protocol": 17, "dst_ports": [], "src_ports": [123, 389] })
            ),
            "udp src 123,389"
        );
        assert_eq!(
            summary(serde_json::json!({ "protocol": 17, "fragment": "non_first" })),
            "udp non-first fragments"
        );
        assert_eq!(
            summary(serde_json::json!({
                "protocol": 17, "src_ports": [11211],
                "packet_length": { "min": 1000, "max": 65535 }
            })),
            "udp src 11211 len 1000-65535"
        );
        assert_eq!(
            summary(serde_json::json!({ "protocol": 6, "dst_ports": [80, 443] })),
            "tcp dst 80,443"
        );
    }

    #[test]
    fn peer_commands_distinguish_observation_results_and_accept_older_health() {
        for (status, supported) in [
            ("connected", true),
            ("unsupported", false),
            ("error", false),
        ] {
            let health: HealthResponse = serde_json::from_value(serde_json::json!({
                "status": "healthy", "bgp_sessions": {}, "active_mitigations": 0,
                "database": "connected", "gobgp": { "status": status }
            }))
            .unwrap();
            assert!(health.speaker.is_none());
            assert_eq!(health.require_peer_observation().is_ok(), supported);
            if status == "unsupported" {
                assert!(
                    health
                        .require_peer_observation()
                        .unwrap_err()
                        .contains("unsupported")
                );
            }
            // Successful JSON output remains the original peer-name/state map.
            assert_eq!(
                serde_json::to_value(&health.bgp_sessions).unwrap(),
                serde_json::json!({})
            );
        }
        let health: HealthResponse = serde_json::from_value(serde_json::json!({
            "status": "degraded", "bgp_sessions": {}, "active_mitigations": 0,
            "database": "connected", "gobgp": { "status": "error", "error": "RPC unavailable" },
            "speaker": { "backend": "rustbgpd", "capabilities": { "rule_reader": true, "peer_observer": true } }
        })).unwrap();
        assert_eq!(health.speaker.as_ref().unwrap().backend, "rustbgpd");
        assert!(
            health
                .require_peer_observation()
                .unwrap_err()
                .contains("RPC unavailable")
        );
    }
    #[test]
    fn daemon_health_metadata_keeps_zero_missing_version_and_unavailable_states() {
        for status in ["observed", "error", "unsupported"] {
            let daemon: DaemonHealthObservation = serde_json::from_value(serde_json::json!({
                "status": status, "version": null,
                "uptime_seconds": if status == "observed" { Some(0_u64) } else { None },
                "ready": if status == "observed" { Some(false) } else { None },
                "observed_at": if status == "observed" { Some("2026-01-01T00:00:00Z") } else { None }
            })).unwrap();
            assert_eq!(daemon.status, status);
            assert!(daemon.version.is_none());
            assert_eq!(
                daemon.uptime_seconds,
                if status == "observed" { Some(0) } else { None }
            );
        }
    }
}
