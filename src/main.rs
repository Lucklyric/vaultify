//! Main entry point for vaultify.

use clap::Parser;
use colored::Colorize;
use dialoguer::Confirm;
use std::path::PathBuf;
use vaultify::cli::Cli;
use vaultify::interactive::InteractiveVault;
use vaultify::utils::error_exit;

#[tokio::main]
async fn main() {
    // Set up colored output for Windows
    #[cfg(windows)]
    colored::control::set_virtual_terminal(true).ok();

    // Clean up any old temp files from previous sessions
    let _ = vaultify::secure_temp::cleanup_old_temp_files();

    // Parse command line arguments
    let args = std::env::args().collect::<Vec<_>>();

    // Check if running in interactive mode (no subcommand)
    if args.len() == 1 || (args.len() == 3 && (args[1] == "-f" || args[1] == "--file")) {
        // Interactive mode
        run_interactive().await;
    } else {
        // CLI mode
        run_cli().await;
    }

    // Clean up temp files on exit
    let _ = vaultify::secure_temp::cleanup_old_temp_files();
}

/// Run in CLI mode.
async fn run_cli() {
    let cli = Cli::parse();

    if let Err(e) = cli.execute().await {
        error_exit(&e.to_string(), 1);
    }
}

/// Run in interactive mode.
async fn run_interactive() {
    // Parse just the file argument if provided
    let args: Vec<String> = std::env::args().collect();
    let vault_path = if args.len() == 3 && (args[1] == "-f" || args[1] == "--file") {
        PathBuf::from(&args[2])
    } else if let Ok(path) = std::env::var("VAULT_FILE") {
        PathBuf::from(path)
    } else {
        // Try to find vault file
        if let Some(path) = vaultify::utils::find_vault_file() {
            path
        } else {
            // No vault file found, prompt user to create one
            eprintln!("{}", "No vault file found.".yellow());

            let vault_path = PathBuf::from("vault.md");
            let full_path = std::env::current_dir()
                .unwrap_or_default()
                .join(&vault_path);

            // Check if we're in an interactive terminal
            let create = if atty::is(atty::Stream::Stdin) && atty::is(atty::Stream::Stdout) {
                match Confirm::new()
                    .with_prompt(format!(
                        "Would you like to create a new vault at '{}'?",
                        full_path.display()
                    ))
                    .default(true)
                    .interact()
                {
                    Ok(answer) => answer,
                    Err(_) => {
                        eprintln!(
                            "{}",
                            "Unable to read input. Use 'vaultify init' to create a vault.".yellow()
                        );
                        false
                    }
                }
            } else {
                // Non-interactive mode, inform user
                eprintln!("{}", "Run 'vaultify init' to create a new vault, or run vaultify in an interactive terminal.".yellow());
                false
            };

            if create {
                // Create new vault file
                let content = vaultify::parser::VaultParser::create_root_document();
                match std::fs::write(&vault_path, content) {
                    Ok(_) => {
                        // Set secure permissions
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let permissions = std::fs::Permissions::from_mode(0o600);
                            let _ = std::fs::set_permissions(&vault_path, permissions);
                        }

                        println!("{} Created vault at: {}", "✓".green(), vault_path.display());
                        vault_path
                    }
                    Err(e) => error_exit(&format!("Failed to create vault: {e}"), 1),
                }
            } else {
                error_exit(
                    "No vault file available. Use 'vaultify init' to create one.",
                    1,
                )
            }
        }
    };

    // Create and run interactive vault
    match InteractiveVault::new(vault_path) {
        Ok(mut vault) => {
            if let Err(e) = vault.run().await {
                error_exit(&e.to_string(), 1);
            }
        }
        Err(e) => {
            error_exit(&e.to_string(), 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        // Test that CLI can be parsed without panicking
        let cli = Cli::try_parse_from(["vaultify", "list"]);
        assert!(cli.is_ok());

        let cli = Cli::try_parse_from(["vaultify", "list", "--tree"]);
        assert!(cli.is_ok());
    }
}
