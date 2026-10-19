#![forbid(unsafe_code)]
#![deny(clippy::allow_attributes_without_reason)]

use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
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
    vector: String,
    action_type: String,
    rate_bps: Option<u64>,
    #[serde(default)]
    protocol: Option<u8>,
    #[serde(default)]
    dst_ports: Vec<u16>,
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
    /// One-line match, for example `udp src 123,389` or `udp non-first fragments`.
    fn match_summary(&self) -> String {
        if self.blackhole.is_some() || self.action_type == "blackhole" {
            return "all traffic".into();
        }
        let join = |ports: &[u16]| {
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        let mut parts = vec![match self.protocol {
            None => "any".to_string(),
            Some(1) => "icmp".into(),
            Some(6) => "tcp".into(),
            Some(17) => "udp".into(),
            Some(58) => "icmpv6".into(),
            Some(other) => other.to_string(),
        }];
        if !self.src_ports.is_empty() {
            parts.push(format!("src {}", join(&self.src_ports)));
        }
        if !self.dst_ports.is_empty() {
            parts.push(format!("dst {}", join(&self.dst_ports)));
        }
        if let Some(fragment) = &self.fragment {
            parts.push(match fragment.as_str() {
                "non_first" => "non-first fragments".into(),
                other => format!("fragment {other}"),
            });
        }
        if let Some(length) = &self.packet_length {
            parts.push(format!("len {}-{}", length.min, length.max));
        }
        parts.join(" ")
    }
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
}

impl Client {
    fn new(base_url: String, token: Option<String>) -> Self {
        Self {
            base_url,
            token,
            http: reqwest::Client::new(),
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.request(method, &url);
        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
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
    let client = Client::new(cli.api, cli.token);

    let result = match cli.command {
        Commands::Status => cmd_status(&client, cli.format).await,
        Commands::Mitigations(cmd) => cmd_mitigations(&client, cmd, cli.format).await,
        Commands::Safelist(cmd) => cmd_safelist(&client, cmd, cli.format).await,
        Commands::Operators(cmd) => cmd_operators(cmd, cli.format).await,
        Commands::Peers => cmd_peers(&client, cli.format).await,
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

async fn cmd_mitigations(
    client: &Client,
    cmd: MitigationCommands,
    format: OutputFormat,
) -> Result<(), String> {
    match cmd {
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
                            m.victim_ip,
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
                    println!("Victim IP:      {}", m.victim_ip);
                    println!("Vector:         {}", m.vector);
                    println!("Action:         {}", m.action_type);
                    println!("Match:          {}", m.match_summary());
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
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
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
