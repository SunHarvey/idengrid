use anyhow::Result;
use clap::Parser;
use idengrid_agent::{
    agent::{RuntimeOptions, run_with_shutdown},
    config::{load_config_file, load_config_stdin},
    redaction::redact,
};
use std::path::PathBuf;
use tokio::sync::oneshot;
use tracing::error;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "idengrid-agent",
    about = "Fail-closed native IdenGrid Edge agent"
)]
struct Arguments {
    /// Read configuration from this regular 0600 file; stdin is used when omitted.
    #[arg(long, value_name = "0600_JSON_FILE")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_current_span(false)
        .with_span_list(false)
        .init();
    if let Err(error) = execute().await {
        error!(error = %redact(&format!("{error:#}")), "agent terminated with an error");
        std::process::exit(1);
    }
}

async fn execute() -> Result<()> {
    let arguments = Arguments::parse();
    let config = match arguments.config {
        Some(path) => load_config_file(&path)?,
        None => load_config_stdin()?,
    };
    let (ready_tx, _ready_rx) = oneshot::channel();
    run_with_shutdown(
        config,
        RuntimeOptions::default(),
        ready_tx,
        shutdown_signal(),
    )
    .await
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let terminate = signal(SignalKind::terminate());
        match terminate {
            Ok(mut terminate) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result { error!(error = %error, "Ctrl-C handler failed"); }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                error!(error = %error, "SIGTERM handler failed");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(error = %error, "Ctrl-C handler failed");
        }
    }
}
