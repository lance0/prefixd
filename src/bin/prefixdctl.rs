use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "prefixdctl", about = "Control CLI for prefixd", version)]
struct Cli {
    /// prefixd API endpoint
    #[arg(short, long, default_value = "http://127.0.0.1:8080", env = "PREFIXD_API")]
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

    /// Show BGP peer status
    Peers,

    /// Reload configuration (inventory, playbooks)
    Reload,
}

#[derive(Subcommand)]
enum MitigationCommands {
    /// List active mitigations
    List {
        /// Filter by status (active, escalated, expired, withdrawn)
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
    created_at: String,
    expires_at: String,
    scope_hash: String,
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
        Commands::Peers => cmd_peers(&client, cli.format).await,
        Commands::Reload => cmd_reload(&client, cli.format).await,
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
    let health: HealthResponse = client.get("/v1/health").await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&health).unwrap());
        }
        OutputFormat::Table => {
            println!("Status: {}", health.status);
            println!("Active Mitigations: {}", health.active_mitigations);
            println!();
            println!("Components:");
            let db_indicator = if health.database == "connected" { "●" } else { "○" };
            println!("  {} Database: {}", db_indicator, health.database);
            let gobgp_indicator = if health.gobgp.status == "connected" { "●" } else { "○" };
            if let Some(ref err) = health.gobgp.error {
                println!("  {} GoBGP: {} ({})", gobgp_indicator, health.gobgp.status, err);
            } else {
                println!("  {} GoBGP: {}", gobgp_indicator, health.gobgp.status);
            }
            println!();
            println!("BGP Sessions:");
            if health.bgp_sessions.is_empty() {
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
        MitigationCommands::List { status, customer, limit } => {
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
                    println!("{}", serde_json::to_string_pretty(&resp.mitigations).unwrap());
                }
                OutputFormat::Table => {
                    if resp.mitigations.is_empty() {
                        println!("No mitigations found.");
                        return Ok(());
                    }

                    println!(
                        "{:<36}  {:<10}  {:<15}  {:<10}  {:<8}  {}",
                        "ID", "STATUS", "VICTIM_IP", "VECTOR", "ACTION", "EXPIRES"
                    );
                    println!("{}", "-".repeat(100));

                    for m in &resp.mitigations {
                        let expires = &m.expires_at[..19]; // Trim to datetime
                        println!(
                            "{:<36}  {:<10}  {:<15}  {:<10}  {:<8}  {}",
                            m.mitigation_id, m.status, m.victim_ip, m.vector, m.action_type, expires
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
                    if let Some(rate) = m.rate_bps {
                        println!("Rate (bps):     {}", rate);
                    }
                    println!("Customer:       {}", m.customer_id.as_deref().unwrap_or("N/A"));
                    println!("Created:        {}", m.created_at);
                    println!("Expires:        {}", m.expires_at);
                    println!("Scope Hash:     {}", m.scope_hash);
                }
            }
        }

        MitigationCommands::Withdraw { id, reason, operator } => {
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
                        "{:<20}  {:<15}  {:<20}  {}",
                        "PREFIX", "ADDED_BY", "ADDED_AT", "REASON"
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

        SafelistCommands::Add { prefix, reason, operator } => {
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
    let health: HealthResponse = client.get("/v1/health").await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&health.bgp_sessions).unwrap());
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
    let resp: ReloadResponse = client.post("/v1/config/reload", &serde_json::json!({})).await?;

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
