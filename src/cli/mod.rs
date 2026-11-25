// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

pub mod handler;
pub mod http;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "netevd")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/netevd/netevd.yaml")]
    pub config: PathBuf,

    /// Enable dry-run mode (don't execute scripts or make changes)
    #[arg(long)]
    pub dry_run: bool,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the daemon (default)
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Show daemon status
    Status {
        /// Output format
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,

        #[command(flatten)]
        api: ApiArgs,
    },

    /// List network interfaces
    List {
        /// Resource type to list
        #[arg(value_enum)]
        resource: ListResource,

        /// Output format
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,

        #[command(flatten)]
        api: ApiArgs,
    },

    /// Show details about a resource
    Show {
        /// Resource type
        #[arg(value_enum)]
        resource: ShowResource,

        /// Resource name/identifier
        name: String,

        /// Output format
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,

        #[command(flatten)]
        api: ApiArgs,
    },

    /// Watch events in real-time
    Events {
        /// Follow events (like tail -f)
        #[arg(short, long)]
        follow: bool,

        /// Filter by interface name
        #[arg(short, long)]
        interface: Option<String>,

        /// Filter by event type
        #[arg(short = 't', long)]
        event_type: Option<String>,

        /// Number of recent events to show
        #[arg(short = 'n', long, default_value = "10")]
        tail: usize,

        /// Output format
        #[arg(short = 'o', long, default_value = "text")]
        format: OutputFormat,

        /// Only events with this outcome
        #[arg(long, value_parser = ["dispatched", "failed", "rate-limited"])]
        outcome: Option<String>,

        #[command(flatten)]
        api: ApiArgs,
    },

    /// Reload configuration
    Reload {
        #[command(flatten)]
        api: ApiArgs,
    },

    /// Check the configuration: line-numbered errors and warnings
    #[command(name = "check-config", alias = "validate")]
    Validate {
        /// Configuration file to check (default: the global --config)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Treat warnings (unknown keys, risky values) as failures
        #[arg(long)]
        strict: bool,

        /// Output format (text or json)
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,
    },

    /// Show which scripts would run for an event, without running anything
    Explain {
        /// Hook state, e.g. routable, address-added, mtu
        #[arg(required_unless_present = "from_file")]
        event: Option<String>,

        /// Interface name
        #[arg(short, long, default_value = "eth0")]
        link: String,

        /// Interface index
        #[arg(long, default_value_t = 2)]
        index: u32,

        /// Event source (netlink applies the interface selector)
        #[arg(long, default_value = "netlink")]
        backend: String,

        /// Address on the interface (repeatable)
        #[arg(long = "address")]
        addresses: Vec<String>,

        /// Hook root directory (default /etc/netevd)
        #[arg(long)]
        config_root: Option<PathBuf>,

        /// Replay recorded netevd.event.v1 events, one JSON object per line
        #[arg(long, conflicts_with = "event")]
        from_file: Option<PathBuf>,

        /// Output format (text or json)
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,
    },

    /// Check a running daemon; exits non-zero when it is not ready
    Health {
        /// Output format (text or json)
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,

        #[command(flatten)]
        api: ApiArgs,
    },

    /// Run the hook scripts for a synthetic or recorded event, now, as the
    /// current user (changes nothing unless your scripts do)
    Trigger {
        /// Hook state, e.g. routable, address-added, mtu
        #[arg(required_unless_present = "from_file")]
        event: Option<String>,

        /// Interface name
        #[arg(short, long, default_value = "eth0")]
        link: String,

        /// Interface index
        #[arg(long, default_value_t = 2)]
        index: u32,

        /// Event source (netlink applies the interface selector)
        #[arg(long, default_value = "netlink")]
        backend: String,

        /// Address on the interface (repeatable)
        #[arg(long = "address")]
        addresses: Vec<String>,

        /// Hook root directory (default /etc/netevd)
        #[arg(long)]
        config_root: Option<PathBuf>,

        /// Replay recorded netevd.event.v1 events, one JSON object per line
        #[arg(long, conflicts_with = "event")]
        from_file: Option<PathBuf>,

        /// Per-script timeout in seconds (default: hooks.timeout_sec)
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86400))]
        timeout: Option<u64>,

        /// Allow running as root (the daemon runs scripts as `netevd`)
        #[arg(long)]
        allow_root: bool,

        /// Output format (text or json)
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,
    },

    /// Test a script execution
    Test {
        /// Path to script to test
        script: PathBuf,

        /// Interface name for testing
        #[arg(short, long, default_value = "eth0")]
        interface: String,

        /// Event type for testing
        #[arg(short = 't', long, default_value = "routable")]
        event_type: String,

        /// IP address for testing
        #[arg(long)]
        ip: Option<String>,
    },

    /// Show version information
    Version {
        /// Show detailed version info
        #[arg(short, long)]
        detailed: bool,
    },
}

/// Where the daemon's API is and how to authenticate to it.
#[derive(clap::Args, Debug, Clone)]
pub struct ApiArgs {
    /// API endpoint (http or https)
    #[arg(long, env = "NETEVD_ENDPOINT", default_value = "http://localhost:9090")]
    pub endpoint: String,

    /// File containing the API bearer token (or set NETEVD_API_TOKEN)
    #[arg(long, env = "NETEVD_API_TOKEN_FILE")]
    pub token_file: Option<PathBuf>,

    /// Trust only this PEM CA certificate for https (default: system store)
    #[arg(long, env = "NETEVD_API_CA_FILE")]
    pub ca_file: Option<PathBuf>,
}

impl ApiArgs {
    /// Client settings, taking a literal token from `NETEVD_API_TOKEN`.
    pub fn options(&self) -> http::ClientOptions {
        http::ClientOptions {
            endpoint: self.endpoint.clone(),
            token_file: self.token_file.clone(),
            token: std::env::var("NETEVD_API_TOKEN").ok(),
            ca_file: self.ca_file.clone(),
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Text,
    Json,
    Yaml,
    Table,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ListResource {
    Interfaces,
    Routes,
    Rules,
    Scripts,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ShowResource {
    Interface,
    Route,
    Rule,
    Status,
}

impl Cli {
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// Catches clashing short options and other definition mistakes, which
    /// otherwise panic only when the affected subcommand is used.
    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn events_follow_and_format_do_not_clash() {
        let c = Cli::try_parse_from(["netevd", "events", "-f", "-o", "json"]).unwrap();
        match c.command {
            Some(Commands::Events { follow, format, .. }) => {
                assert!(follow);
                assert!(matches!(format, OutputFormat::Json));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bad_values_are_rejected_by_the_parser() {
        for args in [
            vec!["netevd", "events", "--outcome", "bogus"],
            vec!["netevd", "trigger", "mtu", "--timeout", "0"],
            vec!["netevd", "trigger"],
            vec!["netevd", "trigger", "mtu", "--from-file", "x"],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        }
    }
}
