use clap::Parser;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use vibe_daemon::config::Config;
use vibe_daemon::mcp::McpDispatcher;

#[derive(Parser, Debug)]
#[command(
    name = "vibe-daemon",
    author,
    version,
    about = "vibe-daemon - Model Context Protocol (MCP) server over stdio"
)]
struct Cli {
    /// Optional path to TOML configuration file. If omitted, safe defaults are used.
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,

    /// Optional path to log file. If omitted, structured logs are written to stderr.
    #[arg(short = 'f', long)]
    log_file: Option<PathBuf>,

    /// Optional path to structured JSONL audit log file. Overrides config file if specified.
    #[arg(short = 'a', long)]
    audit_log: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error). Overrides config file if specified.
    #[arg(short = 'l', long)]
    log_level: Option<String>,

    /// Transport mode: stdio, http, or sse (default: stdio).
    #[arg(short = 't', long, default_value = "stdio")]
    transport: String,

    /// Host interface to bind for network transports (default: 127.0.0.1).
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on for network transports (default: 8900).
    #[arg(short = 'p', long, default_value_t = 8900)]
    port: u16,
}

fn init_logging(cli: &Cli, config: &Config) -> anyhow::Result<()> {
    let effective_log_level = cli.log_level.as_deref().unwrap_or(&config.daemon.log_level);

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(effective_log_level));

    if let Some(ref path) = cli.log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(file)
                    .with_ansi(false),
            )
            .init();
    } else {
        // Critical requirement: logs MUST be directed to stderr so stdout is reserved for JSON-RPC in stdio mode
        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_ansi(false),
            )
            .init();
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut config = Config::load(cli.config.as_deref()).map_err(|err| {
        eprintln!("Configuration Error: {err}");
        anyhow::anyhow!("{err}")
    })?;
    if let Some(ref audit_path) = cli.audit_log {
        config.daemon.audit_log_path = Some(audit_path.clone());
    }
    init_logging(&cli, &config)?;

    let transport_type: vibe_daemon::transport::TransportType =
        cli.transport.parse().unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(1);
        });

    info!(
        version = env!("CARGO_PKG_VERSION"),
        transport = %transport_type,
        "Starting vibe-daemon MCP server"
    );

    let dispatcher = McpDispatcher::try_with_config(config).map_err(|err| {
        eprintln!("CRITICAL: Audit log integrity failure (fail-closed): {err}");
        anyhow::anyhow!("Audit log integrity verification failed: {err}")
    })?;
    let audit_logger = dispatcher.audit_logger.clone();
    let event_producer = vibe_daemon::events::spawn_system_event_producer(
        dispatcher.config.clone(),
        dispatcher.event_bus.clone(),
        vibe_daemon::events::SystemEventCheckOptions::default(),
        std::time::Duration::from_secs(30),
    );

    let transport_result = match transport_type {
        vibe_daemon::transport::TransportType::Stdio => {
            vibe_daemon::transport::run_stdio(dispatcher).await
        }
        vibe_daemon::transport::TransportType::Http
        | vibe_daemon::transport::TransportType::Sse => {
            vibe_daemon::transport::run_http(dispatcher, &cli.host, cli.port, transport_type).await
        }
    };

    event_producer.abort();
    let _ = event_producer.await;

    audit_logger.flush().await.map_err(anyhow::Error::msg)?;
    transport_result?;
    info!("vibe-daemon stopped cleanly");
    Ok(())
}
