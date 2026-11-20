//! `rsim-inventory`: the schema of the inventory database, the import of an
//! env file of the collector, a print of the inventory, and the users of
//! `rsim-api`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rsim_inventory::{
    CA_FILE_VAR, Db, ResolvedDevices, Role, URL_VAR, env, hash_password, import_changes,
};

/// The actor of the audit records of an import.
const IMPORT_ACTOR: &str = "rsim-inventory import-env";
/// The actor of the sign-in events of a user command.
const USER_ACTOR: &str = "rsim-inventory";

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
    /// Makes or changes a user of rsim-api.
    #[command(subcommand)]
    User(UserCommand),
}

#[derive(Subcommand)]
enum UserCommand {
    /// Makes a user. The password is the first line of standard input. An
    /// existing name is refused.
    Add {
        name: String,
        /// viewer, operator or admin.
        #[arg(long, default_value = "viewer")]
        role: String,
    },
    /// Gives a user a new password, from the first line of standard input,
    /// and ends the sessions of the user. The role and the state stay.
    Password { name: String },
    /// Disables a user and ends the sessions of the user.
    Disable { name: String },
    /// Lists the users.
    List,
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
        Command::User(cmd) => {
            db.migrate().await.map_err(|e| e.to_string())?;
            let e = |e: rsim_inventory::Error| e.to_string();
            match cmd {
                UserCommand::Add { name, role } => {
                    let role = Role::parse(&role)
                        .ok_or(format!("{role} is not viewer, operator or admin"))?;
                    if db.users().await.map_err(e)?.iter().any(|u| u.name == name) {
                        return Err(format!(
                            "{name} is a user; use user password to change its password"
                        ));
                    }
                    let hash = hash_password(&read_password()?).map_err(e)?;
                    let u = db
                        .put_user(USER_ACTOR, &name, role, false, Some(&hash))
                        .await
                        .map_err(e)?;
                    println!("{} is a user with the role {}", u.name, u.role.word());
                }
                UserCommand::Password { name } => {
                    let users = db.users().await.map_err(e)?;
                    let u = users
                        .iter()
                        .find(|u| u.name == name)
                        .ok_or(format!("{name} is not a user"))?;
                    let hash = hash_password(&read_password()?).map_err(e)?;
                    db.put_user(USER_ACTOR, &name, u.role, u.disabled, Some(&hash))
                        .await
                        .map_err(e)?;
                    println!("{name} has a new password");
                }
                UserCommand::Disable { name } => {
                    let users = db.users().await.map_err(e)?;
                    let u = users
                        .iter()
                        .find(|u| u.name == name)
                        .ok_or(format!("{name} is not a user"))?;
                    db.put_user(USER_ACTOR, &name, u.role, true, None)
                        .await
                        .map_err(e)?;
                    println!("{name} is disabled");
                }
                UserCommand::List => {
                    let users = db.users().await.map_err(e)?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&users).map_err(|e| e.to_string())?
                    );
                }
            }
        }
    }
    Ok(())
}

/// The first line of standard input with no line end.
fn read_password() -> Result<String, String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("standard input: {e}"))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
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
