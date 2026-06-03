use clap::Parser;
use log::LevelFilter;
use psocket::Ipv4Addr;
use simple_logger::SimpleLogger;
use std::env;
use std::path::Path;
use std::str;
use std::thread;
use std::time::Duration;

#[path = "../utils/kports.rs"]
mod kports;
#[path = "../utils/options.rs"]
mod options;
#[path = "../utils/socket.rs"]
mod socket;

fn main() {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .env()
        .init()
        .unwrap();

    let mut knocker = match Knocker::build_knocker() {
        Ok(kr) => kr,
        Err(err) => {
            log::error!("Error preparing configuration: {}", err);
            std::process::exit(1);
        }
    };

    // Create the state directory if it does not already exist
    match knocker.ensure_state_dir() {
        Ok(_) => {}
        Err(err) => {
            log::error!("Error ensuring state directory: {}", err);
            std::process::exit(1);
        }
    };

    let mut success = false;

    while !success {
        log::debug!("attempting knock sequence");

        match knocker.update_state() {
            Ok(_) => {}
            Err(err) => {
                log::error!("Error updating state: {}", err);
                std::process::exit(1);
            }
        };

        // Avoid starting a sequence too close to an interval rollover. A small
        // clock skew between client and daemon is enough to desynchronize the
        // sequence if we start in the final seconds of an interval.
        let interval_remaining = match knocker.interval_remaining() {
            Ok(v) => v,
            Err(err) => {
                log::error!("Error calculating interval headroom: {}", err);
                std::process::exit(1);
            }
        };
        let min_headroom = knocker.estimated_headroom_secs();
        if interval_remaining <= min_headroom {
            log::info!(
                "Only {}s remain in this interval; waiting for the next interval before knocking",
                interval_remaining
            );
            thread::sleep(Duration::from_secs(interval_remaining));
            continue;
        }

        // Try a small adjacent-interval window to tolerate clock skew between
        // the client and the daemon.
        let candidate_timestamps = knocker.candidate_timestamps();
        for timestamp in candidate_timestamps {
            let kport_values: Vec<u32> = kports::calculate_kports_for_timestamp(
                knocker.knock_common.secret_value.clone().into(),
                timestamp,
                knocker.knock_common.counter,
                knocker.knock_common.num_ports,
                knocker.knock_common.port_range.clone(),
            );
            log::trace!("timestamp: {timestamp}, kport_values: {:?}", kport_values);

            success = match socket::knock_ports(
                knocker.ip_address,
                knocker.knock_common.dest_port,
                kport_values,
            ) {
                Ok(s) => s,
                Err(err) => {
                    log::error!("Error performing knock sequence: {}", err);
                    std::process::exit(1);
                }
            };

            if success {
                break;
            }
        }

        // Only advance the counter after a successful destination connection so
        // the client stays in sync with the daemon's state for this interval.
        if success {
            knocker.knock_common.counter += 1;
        }
    }

    match knocker.update_state() {
        Ok(_) => {}
        Err(err) => {
            log::error!("Error updating state: {}", err);
            std::process::exit(1);
        }
    };
}

/************************************************************************************/
/* Knocker                                                                          */
/************************************************************************************/

const KNOCKER_CONFIG_VAR_NAME: &str = "TOTP_KNOCKER_CONFIG_PATH";
const KNOCKER_STATE_VAR_NAME: &str = "TOTP_KNOCKER_STATE_DIR";

/// Time-based One-time Passcode Port Knocker
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct KnockerArgs {
    /// Literal string value for the secret. Mutually exclusive with '--secret-file'
    #[arg(long)]
    secret_value: Option<String>,
    /// Path to file containing secret. Mutually exclusive with '--secret-value'
    #[arg(long)]
    secret_path: Option<String>,

    /// Interval at which to change knocking sequences, specified in seconds. Optional, default is 30
    #[arg(long)]
    time_interval: Option<u64>,

    /// Minimum port to number to use for knocking. Optional, default is 1024
    #[arg(long)]
    min_port: Option<u32>,
    /// Maximum port to number to use for knocking. Optional, default is 32768
    #[arg(long)]
    max_port: Option<u32>,

    /// Number of ports to use in the sequence. Optional, default is 32
    #[arg(long)]
    num_ports: Option<u32>,

    /// Port to open when the knocking sequence is complete.
    #[arg(long)]
    dest_port: Option<u32>,

    ip_address: Ipv4Addr,
}

#[derive(Clone, Debug)]
pub struct Knocker {
    pub knock_common: options::KnockCommon,
    pub ip_address: Ipv4Addr,
}

impl Knocker {
    pub fn build_knocker() -> Result<Knocker, Box<dyn std::error::Error>> {
        log::info!("Entering build_knocker");
        let args = KnockerArgs::parse();

        // Determine configuration file path based on env var
        let config_path_string: String = match env::var(KNOCKER_CONFIG_VAR_NAME) {
            Ok(cps) => cps,
            Err(_) => {
                // Next check to see if XDG_CONFIG_HOME is set
                match env::var("XDG_CONFIG_HOME") {
                    Ok(xch) => xch + "totp-knocker/knocker.toml",
                    Err(_) => {
                        // Finally construct from user home directory
                        match env::var("HOME") {
                            Ok(hm) => hm + "/.config/totp-knocker/knocker.toml",
                            Err(_) => {
                                log::error!("User has no HOME variable set");
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }
        };
        log::debug!("config_path_string: {config_path_string}");
        let config_path: &Path = Path::new(&config_path_string);
        log::debug!("config_path: {}", config_path.display());

        // Determine state file path based on env var
        let state_dir_string: String = match env::var(KNOCKER_STATE_VAR_NAME) {
            Ok(sds) => sds,
            Err(_) => {
                // Next check to see if XDG_STATE_HOME is set
                match env::var("XDG_STATE_HOME") {
                    Ok(xsh) => xsh + "totp-knocker",
                    Err(_) => {
                        // Finally construct from user home directory
                        match env::var("HOME") {
                            Ok(hm) => hm + "/.local/state/totp-knocker",
                            Err(_) => {
                                log::error!("User has no HOME variable set");
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }
        };
        log::debug!("state_dir_string: {state_dir_string}");
        let state_dir: &Path = Path::new(&state_dir_string);
        log::debug!("state_dir: {}", state_dir.display());

        let config = options::get_config(config_path)?;
        let knock_common = options::KnockCommon::build_common(
            state_dir,
            options::KnockArgs {
                secret_value: args.secret_value,
                secret_path: args.secret_path,
                time_interval: args.time_interval,
                min_port: args.min_port,
                max_port: args.max_port,
                num_ports: args.num_ports,
                dest_port: args.dest_port,
            },
            config.clone(),
        )?;

        Ok(Knocker {
            knock_common: knock_common.clone(),
            ip_address: args.ip_address,
        })
    }

    pub fn interval_remaining(&self) -> Result<u64, Box<dyn std::error::Error>> {
        self.knock_common.interval_remaining()
    }

    pub fn estimated_headroom_secs(&self) -> u64 {
        // Knocking 32 ports with a short timeout/spacing takes ~8s in the
        // current client implementation. Leave a little extra room so the
        // daemon and client do not straddle an interval boundary.
        10
    }

    pub fn candidate_timestamps(&self) -> Vec<u64> {
        let mut timestamps = vec![self.knock_common.timestamp];

        if self.knock_common.timestamp >= self.knock_common.interval {
            timestamps.push(self.knock_common.timestamp - self.knock_common.interval);
        }

        timestamps.push(self.knock_common.timestamp + self.knock_common.interval);
        timestamps
    }

    pub fn ensure_state_dir(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.knock_common.ensure_state_dir()
    }

    pub fn update_state(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        self.knock_common.update_state()
    }
}
