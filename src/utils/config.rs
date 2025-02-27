use clap::{Parser, ValueEnum};
use std::env;
use std::fs;
use std::str;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use psocket::{Ipv4Addr};
use serde::{Deserialize, Serialize};
use sha256::digest;

const DEFAULT_TIME_INTERVAL: u64 = 30;
const DEFAULT_MIN_PORT: u32 = 1024;
const DEFAULT_MAX_PORT: u32 = 32768;
const DEFAULT_NUM_PORTS: u32 = 32;

#[derive(Deserialize, Serialize, Debug, Clone)]
struct KnockState {
    pub timestamp: u64,
    pub counter: u32,
    pub config_digest: String,
}

/************************************************************************************/
/* Knock Daemon                                                                     */
/************************************************************************************/

const DAEMON_CONFIG_VAR_NAME: &str = "TOTP_KNOCKD_CONFIG_PATH";
const DAEMON_STATE_VAR_NAME: &str = "TOTP_KNOCKD_STATE_DIR";

const DAEMON_DEFAULT_CONFIG_PATH: &str = "/etc/totp-knockd/daemon.toml";
const DAEMON_DEFAULT_STATE_DIR: &str = "/var/lib/totp-knockd";

const PID_FILE_NAME: &str = "daemon.pid";
const STATE_FILE_NAME: &str = "state.json";

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum DaemonActionKind {
    /// Start the TOTP Port Knocking Daemon
    Start,

    /// Stop the TOTP Port Knocking Daemon
    Stop,
}

/// Time-based One-time Passcode Port Knocking Daemon
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct DaemonArgs {
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

    action: DaemonActionKind,
}

#[derive(Deserialize)]
struct TOTPKnockdConfig {
   secret_value: Option<String>,
   secret_path: Option<String>,
   time_interval: Option<u64>,
   min_port: Option<u32>,
   max_port: Option<u32>,
   num_ports: Option<u32>,
   dest_port: Option<u32>,
}

#[derive(Deserialize)]
struct DaemonConfig {
   totp_knockd: TOTPKnockdConfig,
}

#[derive(Clone, Debug)]
pub struct KnockDaemon {
    pub state_dir: PathBuf,
    pub secret_value: String,
    pub dest_port: u32,
    pub num_ports: u32, 
    pub port_range: Vec<u32>,
    pub interval: u64,
    pub timestamp: u64,
    pub counter: u32,
    pub action: DaemonActionKind,
}

impl KnockDaemon {
    pub fn interval_remaining(&self) -> u64 {
        log::info!("Entering interval_remaining");
        let cur_time_secs: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let interval_remaining = cur_time_secs % self.interval;
        log::debug!("interval_remaining: {interval_remaining}");

        interval_remaining
    }

    pub fn ensure_state_dir(&self) {
        log::info!("Entering ensure_state_dir");
        log::debug!("state_dir: {}", self.state_dir.display());

        if !Path::new(&self.state_dir).is_dir() {
            log::debug!("creating state directory");
            fs::create_dir(self.state_dir.clone()).unwrap();
        } else {
            log::debug!("state directory already exists");
        }
    }

    pub fn save_pid(&self, pid: i32) {
        log::info!("Entering save_pid");
        log::debug!("pid: {pid}");
        let pidfile_path: PathBuf = Path::new(&self.state_dir).join(PID_FILE_NAME);

        log::debug!("pidfile_path: {}", pidfile_path.display());
        fs::write(pidfile_path, pid.to_string()).unwrap();
    }

    pub fn read_pid(&self) -> i32 {
        log::info!("Entering read_pid");
        let pidfile_path: PathBuf = Path::new(&self.state_dir).join(PID_FILE_NAME);

        // Read pidfile and convert contents to i32
        log::debug!("pidfile_path: {}", pidfile_path.display());
        let pidfile_contents = fs::read(pidfile_path).unwrap();
        let pidfile_string = str::from_utf8(&pidfile_contents).unwrap();

        let pid: i32 = pidfile_string.parse().unwrap();

        log::debug!("pid: {pid}");
        pid
    }

    pub fn clean_pid(&self) {
        log::info!("Entering clean_pid");
        let pidfile_path: PathBuf = Path::new(&self.state_dir).join(PID_FILE_NAME);

        log::debug!("pidfile_path: {}", pidfile_path.display());
        fs::remove_file(pidfile_path).unwrap();
    }

    pub fn update_state(&mut self) -> bool {
        log::info!("Entering update_state");
        let state_file_path: PathBuf = Path::new(&self.state_dir).join(STATE_FILE_NAME);
        log::debug!("state_file_path: {}", state_file_path.display());

        let mut changed: bool = false;

        let cur_time_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let config_digest: String = digest(
            self.secret_value.clone() +
            &self.num_ports.to_string() +
            &self.port_range[0].to_string() +
            &self.port_range[1].to_string() +
            &self.interval.to_string()
        );

        log::debug!("cur_time_secs: {cur_time_secs}");
        log::debug!("config_digest: {config_digest}");

        let mut knock_state: KnockState = if Path::new(&state_file_path).is_file() {
            log::debug!("state file already exists");
            self.read_state()
        } else {
            log::debug!("state file did not already exist");
            changed = true;

            KnockState{
                config_digest: config_digest.clone(),
                timestamp: cur_time_secs - (cur_time_secs % self.interval),
                counter: 0,
            }
        };

        log::trace!("knock_state (before): {knock_state:?}");
        log::trace!("changed (before): {changed}");

        // Check if configuration hash changed
        if config_digest != knock_state.config_digest {
            log::debug!("config_digest changed");
            changed = true;

            knock_state.config_digest = config_digest.clone();
            knock_state.counter = 0;
            knock_state.timestamp = cur_time_secs - (cur_time_secs % self.interval); 
        }

        // Check if timestamp expired
        if cur_time_secs > knock_state.timestamp + self.interval {
            log::debug!("timestamp expired");
            changed = true;

            knock_state.config_digest = config_digest;
            knock_state.counter = 0;
            knock_state.timestamp = cur_time_secs - (cur_time_secs % self.interval);
        }

        if self.counter > knock_state.counter {
            log::debug!("counter incremented");
            changed = true;

            knock_state.counter = self.counter;
        }

        log::trace!("knock_state (after): {knock_state:?}");
        log::trace!("changed (after): {changed}");

        if changed {
            self.counter = knock_state.counter;
            self.timestamp = knock_state.timestamp;
            self.write_state(knock_state.clone());
        }

        log::debug!("knock_state: {knock_state:?}");
        log::debug!("changed: {changed}");
        log::debug!("self.count: {}", self.counter);
        log::debug!("self.timestamp: {}", self.timestamp);

        changed
    }

    fn read_state(&self) -> KnockState {
        log::info!("Entering read_state");
        let state_file_path: PathBuf = Path::new(&self.state_dir).join(STATE_FILE_NAME);

        log::debug!("state_file_path: {}", state_file_path.display());
        let state_file_contents = fs::read(state_file_path).unwrap();
        let state_file_string = str::from_utf8(&state_file_contents).unwrap();

        let knock_state: KnockState = serde_json::from_str(state_file_string).unwrap();
        log::debug!("knock_state: {knock_state:?}");

        knock_state
    }

    fn write_state(&self, knock_state: KnockState) {
        log::info!("Entering write_state");

        let state_file_path: PathBuf = Path::new(&self.state_dir).join(STATE_FILE_NAME);
        
        log::debug!("state_file_path: {}", state_file_path.display());
        log::debug!("knock_state: {knock_state:?}");

        fs::write(state_file_path, serde_json::ser::to_string(&knock_state).unwrap()).unwrap();
    }
}

pub fn build_knock_daemon() -> KnockDaemon {
    log::info!("Entering build_knock_daemon");
    let args = DaemonArgs::parse();

    // Determine configuration file path based on env var
    let config_path_string: String = match env::var(DAEMON_CONFIG_VAR_NAME) {
        Ok(val) => val,
        Err(_) => DAEMON_DEFAULT_CONFIG_PATH.to_string()
    };
    log::debug!("config_path_string: {config_path_string}");
    let config_path: &Path = Path::new(&config_path_string);
    log::debug!("config_path: {}", config_path.display());

    // Determine state file path based on env var
    let state_dir_string: String = match env::var(DAEMON_STATE_VAR_NAME) {
        Ok(val) => val,
        Err(_) => DAEMON_DEFAULT_STATE_DIR.to_string()
    };
    log::debug!("state_dir_string: {state_dir_string}");
    let state_dir: &Path = Path::new(&state_dir_string);
    log::debug!("state_dir: {}", state_dir.display());

    // If the config file path exists, parse it
    if !config_path.exists() {
        log::error!("Configuration file at '{}' does not exist", config_path.display());
        std::process::exit(1);
    }

    let config_contents = fs::read(config_path).unwrap();
    let config: DaemonConfig = toml::from_str(
        str::from_utf8(
            &config_contents
        ).unwrap()
    ).unwrap();

    let dest_port: u32 = (match args.dest_port {
        Some(arg_val) => {
            log::trace!("dest_port from args");
            Ok(arg_val)
        },
        None => match config.totp_knockd.dest_port {
            Some(conf_val) => {
                log::trace!("dest_port from config");
                Ok(conf_val)
            },
            None => {
                log::error!("Unable to obtain destination port from command line options or configuration file.");
    
                Err("required argument missing")
            }
        }
    }).unwrap();
    log::debug!("dest_port: {dest_port}");

    let arg_secret_value: Option<String> = (match args.secret_path {
        Some(asp) => {
            match args.secret_value {
                Some(_) => {
                    // There should not be both a secret path
                    // and a secret value
                    log::error!("Command line options included both '--secret-path'\
                                and '--secret-value'. Please only specify one.");
                    
                    Err("mutually exclusive options")
                },
                None => {
                    log::trace!("arg_secret_value from path");
                    let secret_file_contents = fs::read(asp).unwrap();
                    
                    Ok(Some(str::from_utf8(&secret_file_contents).unwrap().to_string()))
                }
            }
        }
        None => {
            match args.secret_value {
                Some(asv) => {
                    log::trace!("arg_secret_value from value");
                    Ok(Some(asv))
                },
                None => Ok(None)
            }
        }
    }).unwrap();

    let conf_secret_value: Option<String> = (match config.totp_knockd.secret_path {
        Some(csp) => {
            match config.totp_knockd.secret_value {
                Some(_) => {
                    // There should not be both a secret path
                    // and a secret value
                    log::error!("Command line options included both '--secret-path'\
                                and '--secret-value'. Please only specify one.");
                    
                    Err("mutually exclusive options")
                },
                None => {
                    log::trace!("conf_secret_value from path");
                    let secret_file_contents = fs::read(csp).unwrap();
                    
                    Ok(Some(str::from_utf8(&secret_file_contents).unwrap().to_string()))
                }
            }
        }
        None => {
            match config.totp_knockd.secret_value {
                Some(csv) => {
                    log::trace!("conf_secret_value from value");
                    Ok(Some(csv))
                },
                None => Ok(None)
            }
        }
    }).unwrap();

    let secret_value: String = (match arg_secret_value {
        Some(arg_val) => {
            log::trace!("secet_value from arg");
            Ok(arg_val)
        },
        None => match conf_secret_value {
            Some(conf_val) => {
                log::trace!("secet_value from conf");
                Ok(conf_val)
            },
            None => {
                log::error!("Unable to be obtain secret value from command line options or configuration file");
    
                Err("required argument missing")
            }
        }
    }).unwrap();
    log::debug!("secret_value: {secret_value}");

    let time_interval: u64 = match args.time_interval {
        Some(arg_val) => {
            log::trace!("time_interval from args");
            arg_val
        },
        None => match config.totp_knockd.time_interval {
            Some(conf_val) => {
                log::trace!("time_interval from conf");
                conf_val
            },
            None => {
                log::trace!("time_interval from default");
                DEFAULT_TIME_INTERVAL
            }
        }
    };
    log::debug!("time_interval: {time_interval}");

    let min_port: u32 = match args.min_port {
        Some(arg_val) => {
            log::trace!("min_port from args");
            arg_val
        },
        None => match config.totp_knockd.min_port {
            Some(conf_val) => {
                log::trace!("min_port from conf");
                conf_val
            },
            None => {
                log::trace!("min_port from default");
                DEFAULT_MIN_PORT
            }
        }
    };
    log::debug!("min_port: {min_port}");

    let max_port: u32 = match args.max_port {
        Some(arg_val) => {
            log::trace!("max_port from args");
            arg_val
        },
        None => match config.totp_knockd.max_port {
            Some(conf_val) => {
                log::trace!("max_port from conf");
                conf_val
            },
            None => {
                log::trace!("max_port from default");
                DEFAULT_MAX_PORT
            }
        }
    };
    log::debug!("max_port: {max_port}");

    let port_range = vec![min_port, max_port];

    let num_ports: u32 = match args.num_ports {
        Some(arg_val) => {
            log::trace!("num_ports from args");
            arg_val
        },
        None => match config.totp_knockd.num_ports {
            Some(conf_val) => {
                log::trace!("num_ports from conf");
                conf_val
            },
            None => {
                log::trace!("num_ports from default");
                DEFAULT_NUM_PORTS
            }
        }
    };
    log::debug!("num_ports: {num_ports}");
    log::debug!("action: {:?}", args.action);

    KnockDaemon {
        state_dir: state_dir.to_path_buf(),
        secret_value: secret_value,
        dest_port: dest_port,
        num_ports: num_ports,
        port_range: port_range,
        interval: time_interval,
        timestamp: 0,
        counter: 0,
        action: args.action
    }
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

#[derive(Deserialize)]
struct TOTPKnockerConfig {
   secret_value: Option<String>,
   secret_path: Option<String>,
   time_interval: Option<u64>,
   min_port: Option<u32>,
   max_port: Option<u32>,
   num_ports: Option<u32>,
   dest_port: Option<u32>,
}

#[derive(Deserialize)]
struct KnockerConfig {
   totp_knocker: TOTPKnockerConfig,
}

#[derive(Clone, Debug)]
pub struct Knocker {
    pub state_dir: PathBuf,
    pub secret_value: String,
    pub dest_port: u32,
    pub num_ports: u32, 
    pub port_range: Vec<u32>,
    pub interval: u64,
    pub timestamp: u64,
    pub counter: u32,
    pub ip_address: Ipv4Addr,
}


impl Knocker {
    pub fn interval_remaining(&self) -> u64 {
        log::info!("Entering interval_remaining");
        let cur_time_secs: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let interval_remaining = cur_time_secs % self.interval;
        log::debug!("interval_remaining: {interval_remaining}");

        interval_remaining
    }

    pub fn ensure_state_dir(&self) {
        log::info!("Entering ensure_state_dir");
        log::debug!("state_dir: {}", self.state_dir.display());

        if !Path::new(&self.state_dir).is_dir() {
            log::debug!("creating state directory");
            fs::create_dir(self.state_dir.clone()).unwrap();
        } else {
            log::debug!("state directory already exists");
        }
    }

    pub fn update_state(&mut self) -> bool {
        log::info!("Entering update_state");
        let state_file_path: PathBuf = Path::new(&self.state_dir).join(STATE_FILE_NAME);
        log::debug!("state_file_path: {}", state_file_path.display());

        let mut changed: bool = false;

        let cur_time_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let config_digest: String = digest(
            self.secret_value.clone() +
            &self.num_ports.to_string() +
            &self.port_range[0].to_string() +
            &self.port_range[1].to_string() +
            &self.interval.to_string()
        );

        log::debug!("cur_time_secs: {cur_time_secs}");
        log::debug!("config_digest: {config_digest}");

        let mut knock_state: KnockState = if Path::new(&state_file_path).is_file() {
            log::debug!("state file already exists");
            self.read_state()
        } else {
            log::debug!("state file did not already exist");
            changed = true;

            KnockState{
                config_digest: config_digest.clone(),
                timestamp: cur_time_secs - (cur_time_secs % self.interval),
                counter: 0,
            }
        };

        log::trace!("knock_state (before): {knock_state:?}");
        log::trace!("changed (before): {changed}");

        // Check if configuration hash changed
        if config_digest != knock_state.config_digest {
            log::debug!("config_digest changed");
            changed = true;

            knock_state.config_digest = config_digest.clone();
            knock_state.counter = 0;
            knock_state.timestamp = cur_time_secs - (cur_time_secs % self.interval); 
        }

        // Check if timestamp expired
        if cur_time_secs > knock_state.timestamp + self.interval {
            log::debug!("timestamp expired");
            changed = true;

            knock_state.config_digest = config_digest;
            knock_state.counter = 0;
            knock_state.timestamp = cur_time_secs - (cur_time_secs % self.interval);
        }

        if self.counter > knock_state.counter {
            log::debug!("counter incremented");
            changed = true;

            knock_state.counter = self.counter;
        }

        log::trace!("knock_state (after): {knock_state:?}");
        log::trace!("changed (after): {changed}");

        if changed {
            self.counter = knock_state.counter;
            self.timestamp = knock_state.timestamp;
            self.write_state(knock_state.clone());
        }

        log::debug!("knock_state: {knock_state:?}");
        log::debug!("changed: {changed}");
        log::debug!("self.count: {}", self.counter);
        log::debug!("self.timestamp: {}", self.timestamp);

        changed
    }

    fn read_state(&self) -> KnockState {
        log::info!("Entering read_state");
        let state_file_path: PathBuf = Path::new(&self.state_dir).join(STATE_FILE_NAME);

        log::debug!("state_file_path: {}", state_file_path.display());
        let state_file_contents = fs::read(state_file_path).unwrap();
        let state_file_string = str::from_utf8(&state_file_contents).unwrap();

        let knock_state: KnockState = serde_json::from_str(state_file_string).unwrap();
        log::debug!("knock_state: {knock_state:?}");

        knock_state
    }

    fn write_state(&self, knock_state: KnockState) {
        log::info!("Entering write_state");

        let state_file_path: PathBuf = Path::new(&self.state_dir).join(STATE_FILE_NAME);
        
        log::debug!("state_file_path: {}", state_file_path.display());
        log::debug!("knock_state: {knock_state:?}");

        fs::write(state_file_path, serde_json::ser::to_string(&knock_state).unwrap()).unwrap();
    }
}

pub fn build_knocker() -> Knocker {
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
                        Ok(hm) => hm + "/.local/state/totp-knocker/knocker.toml",
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

    // If the config file path exists, parse it
    if !config_path.exists() {
        log::error!("Configuration file at '{}' does not exist", config_path.display());
        std::process::exit(1);
    }

    let config_contents = fs::read(config_path).unwrap();
    let config: KnockerConfig = toml::from_str(
        str::from_utf8(
            &config_contents
        ).unwrap()
    ).unwrap();

    let dest_port: u32 = (match args.dest_port {
        Some(arg_val) => {
            log::trace!("dest_port from args");
            Ok(arg_val)
        },
        None => match config.totp_knocker.dest_port {
            Some(conf_val) => {
                log::trace!("dest_port from config");
                Ok(conf_val)
            },
            None => {
                log::error!("Unable to obtain destination port from command line options or configuration file.");
    
                Err("required argument missing")
            }
        }
    }).unwrap();
    log::debug!("dest_port: {dest_port}");

    let arg_secret_value: Option<String> = (match args.secret_path {
        Some(asp) => {
            match args.secret_value {
                Some(_) => {
                    // There should not be both a secret path
                    // and a secret value
                    log::error!("Command line options included both '--secret-path'\
                                and '--secret-value'. Please only specify one.");
                    
                    Err("mutually exclusive options")
                },
                None => {
                    log::trace!("arg_secret_value from path");
                    let secret_file_contents = fs::read(asp).unwrap();
                    
                    Ok(Some(str::from_utf8(&secret_file_contents).unwrap().to_string()))
                }
            }
        }
        None => {
            match args.secret_value {
                Some(asv) => {
                    log::trace!("arg_secret_value from value");
                    Ok(Some(asv))
                },
                None => Ok(None)
            }
        }
    }).unwrap();

    let conf_secret_value: Option<String> = (match config.totp_knocker.secret_path {
        Some(csp) => {
            match config.totp_knocker.secret_value {
                Some(_) => {
                    // There should not be both a secret path
                    // and a secret value
                    log::error!("Command line options included both '--secret-path'\
                                and '--secret-value'. Please only specify one.");
                    
                    Err("mutually exclusive options")
                },
                None => {
                    log::trace!("conf_secret_value from path");
                    let secret_file_contents = fs::read(csp).unwrap();
                    
                    Ok(Some(str::from_utf8(&secret_file_contents).unwrap().to_string()))
                }
            }
        }
        None => {
            match config.totp_knocker.secret_value {
                Some(csv) => {
                    log::trace!("conf_secret_value from value");
                    Ok(Some(csv))
                },
                None => Ok(None)
            }
        }
    }).unwrap();

    let secret_value: String = (match arg_secret_value {
        Some(arg_val) => {
            log::trace!("secet_value from arg");
            Ok(arg_val)
        },
        None => match conf_secret_value {
            Some(conf_val) => {
                log::trace!("secet_value from conf");
                Ok(conf_val)
            },
            None => {
                log::error!("Unable to be obtain secret value from command line options or configuration file");
    
                Err("required argument missing")
            }
        }
    }).unwrap();
    log::debug!("secret_value: {secret_value}");

    let time_interval: u64 = match args.time_interval {
        Some(arg_val) => {
            log::trace!("time_interval from args");
            arg_val
        },
        None => match config.totp_knocker.time_interval {
            Some(conf_val) => {
                log::trace!("time_interval from conf");
                conf_val
            },
            None => {
                log::trace!("time_interval from default");
                DEFAULT_TIME_INTERVAL
            }
        }
    };
    log::debug!("time_interval: {time_interval}");

    let min_port: u32 = match args.min_port {
        Some(arg_val) => {
            log::trace!("min_port from args");
            arg_val
        },
        None => match config.totp_knocker.min_port {
            Some(conf_val) => {
                log::trace!("min_port from conf");
                conf_val
            },
            None => {
                log::trace!("min_port from default");
                DEFAULT_MIN_PORT
            }
        }
    };
    log::debug!("min_port: {min_port}");

    let max_port: u32 = match args.max_port {
        Some(arg_val) => {
            log::trace!("max_port from args");
            arg_val
        },
        None => match config.totp_knocker.max_port {
            Some(conf_val) => {
                log::trace!("max_port from conf");
                conf_val
            },
            None => {
                log::trace!("max_port from default");
                DEFAULT_MAX_PORT
            }
        }
    };
    log::debug!("max_port: {max_port}");

    let port_range = vec![min_port, max_port];

    let num_ports: u32 = match args.num_ports {
        Some(arg_val) => {
            log::trace!("num_ports from args");
            arg_val
        },
        None => match config.totp_knocker.num_ports {
            Some(conf_val) => {
                log::trace!("num_ports from conf");
                conf_val
            },
            None => {
                log::trace!("num_ports from default");
                DEFAULT_NUM_PORTS
            }
        }
    };
    log::debug!("num_ports: {num_ports}");
    log::debug!("ip_address: {:?}", args.ip_address);
    
    Knocker{
        state_dir: state_dir.to_path_buf(),
        secret_value: secret_value,
        dest_port: dest_port,
        num_ports: num_ports,
        port_range: port_range,
        interval: time_interval,
        timestamp: 0,
        counter: 0,
        ip_address: args.ip_address
    }
}