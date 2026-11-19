//! `rsim-inventory`: the schema of the inventory database, the import of an
//! env file of the collector, and a print of the inventory.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rsim_inventory::{CA_FILE_VAR, Db, ResolvedDevices, URL_VAR, env, import_changes};

/// The actor of the audit records of an import.
const IMPORT_ACTOR: &str = "rsim-inventory import-env";

#[derive(Parser)]
#[command(name = "rsim-inventory", about = "The inventory database of rsim")]
struct Cli {
    /// The URL of the database: postgres://user:password@host:port/db.
    #[arg(long, env = URL_VAR, hide_env_values = true)]
    database: String,
    /// The PEM file of the CA bundle of the database server, for TLS.
    #[arg(long, env = CA_FILE_VAR)]
    ca_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Applies the migrations that the database does not have.
    Migrate,
    /// Writes the groups, the devices, the routes, the jump hosts and the
    /// credential references of an env file of the collector. A record
    /// with the same name is replaced. No secret is written.
    ImportEnv { file: PathBuf },
    /// Prints the inventory as JSON.
    Show {
        /// Prints the devices with the settings of their groups resolved.
        #[arg(long)]
        resolved: bool,
    },
}

async fn run(cli: Cli) -> Result<(), String> {
    let ca = match &cli.ca_file {
        Some(p) => Some(std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?),
        None => None,
    };
    let db = Db::new(&cli.database, ca.as_deref()).map_err(|e| e.to_string())?;
    match cli.command {
        Command::Migrate => {
            let applied = db.migrate().await.map_err(|e| e.to_string())?;
            if applied.is_empty() {
                println!(
                    "the schema is at version {}",
                    rsim_inventory::schema_version()
                );
            }
            for v in applied {
                println!("applied migration {v}");
            }
        }
        Command::ImportEnv { file } => {
            let text =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            let records = env::import(&env::parse_env(&text))?;
            let (groups, devices) = (records.groups.len(), records.devices.len());
            db.migrate().await.map_err(|e| e.to_string())?;
            let version = db
                .apply(IMPORT_ACTOR, &import_changes(records))
                .await
                .map_err(|e| e.to_string())?;
            println!(
                "{groups} groups and {devices} devices; the inventory is at version {version}"
            );
        }
        Command::Show { resolved } => {
            let inv = db.load().await.map_err(|e| e.to_string())?;
            let text = if resolved {
                let devices = inv.resolve()?;
                serde_json::to_string_pretty(&ResolvedDevices {
                    version: inv.version,
                    devices,
                })
            } else {
                serde_json::to_string_pretty(&inv)
            };
            println!("{}", text.map_err(|e| e.to_string())?);
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
        .and_then(|rt| rt.block_on(run(cli)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
