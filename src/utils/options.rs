use std::fs;
use std::str;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use sha256::digest;

const DEFAULT_TIME_INTERVAL: u64 = 30;
const DEFAULT_MIN_PORT: u32 = 1024;
const DEFAULT_MAX_PORT: u32 = 32768;
const DEFAULT_NUM_PORTS: u32 = 32;


/************************************************************************************/
/* Common                                                                           */
/************************************************************************************/

#[derive(Deserialize, Serialize, Debug, Clone)]
struct KnockState {
    pub timestamp: u64,
    pub counter: u32,
    pub config_digest: String,
}

const STATE_FILE_NAME: &str = "state.json";

#[derive(Deserialize, Clone)]
pub struct TOTPKnockConfig {
   secret_value: Option<String>,
   secret_path: Option<String>,
   time_interval: Option<u64>,
   min_port: Option<u32>,
   max_port: Option<u32>,
   num_ports: Option<u32>,
   dest_port: Option<u32>,
}

#[derive(Deserialize, Clone)]
pub struct KnockConfig {
   totp_knock: TOTPKnockConfig,
}

pub fn get_config(config_path: &Path) ->  Result<TOTPKnockConfig, Box<dyn std::error::Error>> {
    log::info!("Entering get_config");
    log::debug!("config_path: {}", config_path.display());

    // If the config file path exists, parse it
    let config: TOTPKnockConfig = if config_path.exists() {
        let config_contents = fs::read(config_path)?;
        
        let config_outer: KnockConfig = toml::from_str(
            str::from_utf8(
                &config_contents
            )?
        )?;

        config_outer.totp_knock
    } else {
        log::warn!("No configuration file found at '{}'", config_path.display());

        TOTPKnockConfig {
            secret_value: None,
            secret_path: None,
            time_interval: None,
            min_port: None,
            max_port: None,
            num_ports: None,
            dest_port: None,
        }
    };
    
    Ok(config)
}

#[derive(Debug,Clone)]
pub struct KnockArgs {
    pub secret_value: Option<String>,
    pub secret_path: Option<String>,
    pub time_interval: Option<u64>,
    pub min_port: Option<u32>,
    pub max_port: Option<u32>,
    pub num_ports: Option<u32>,
    pub dest_port: Option<u32>,
}

#[derive(Debug,Clone)]
pub struct KnockCommon {
    pub state_dir: PathBuf,
    pub secret_value: String,
    pub dest_port: u32,
    pub num_ports: u32, 
    pub port_range: Vec<u32>,
    pub interval: u64,
    pub timestamp: u64,
    pub counter: u32,
}

impl KnockCommon {
    pub fn build_common(state_dir: &Path, args: KnockArgs, config: TOTPKnockConfig) -> Result<KnockCommon, Box<dyn std::error::Error>> {
        log::info!("Entering build_common");
        log::debug!("state_dir: {}", state_dir.display());

        let dest_port: u32 = (match args.dest_port {
            Some(arg_val) => {
                log::trace!("dest_port from args");
                Ok(arg_val)
            },
            None => match config.dest_port {
                Some(conf_val) => {
                    log::trace!("dest_port from config");
                    Ok(conf_val)
                },
                None => {
                    log::error!("Unable to obtain destination port from command line options or configuration file.");
        
                    Err("required argument missing")
                }
            }
        })?;
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
                        let secret_file_contents = fs::read(asp)?;
                        
                        Ok(Some((str::from_utf8(&secret_file_contents)?).to_string()))
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
        })?;
    
        let conf_secret_value: Option<String> = (match config.secret_path {
            Some(csp) => {
                match config.secret_value {
                    Some(_) => {
                        // There should not be both a secret path
                        // and a secret value
                        log::error!("Command line options included both '--secret-path'\
                                    and '--secret-value'. Please only specify one.");
                        
                        Err("mutually exclusive options")
                    },
                    None => {
                        log::trace!("conf_secret_value from path");
                        let secret_file_contents = fs::read(csp)?;
                        
                        Ok(Some((str::from_utf8(&secret_file_contents)?).to_string()))
                    }
                }
            }
            None => {
                match config.secret_value {
                    Some(csv) => {
                        log::trace!("conf_secret_value from value");
                        Ok(Some(csv))
                    },
                    None => Ok(None)
                }
            }
        })?;
    
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
        })?;
        log::debug!("secret_value: {secret_value}");
    
        let time_interval: u64 = match args.time_interval {
            Some(arg_val) => {
                log::trace!("time_interval from args");
                arg_val
            },
            None => match config.time_interval {
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
            None => match config.min_port {
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
            None => match config.max_port {
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
            None => match config.num_ports {
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
    
        Ok(KnockCommon {
            state_dir: state_dir.to_path_buf(),
            secret_value: secret_value,
            dest_port: dest_port,
            num_ports: num_ports,
            port_range: port_range,
            interval: time_interval,
            counter: 0,
            timestamp: 0
        })
    }

    pub fn interval_remaining(&self) -> Result<u64, Box<dyn std::error::Error>> {
        log::info!("Entering interval_remaining");
        let cur_time_secs: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let interval_remaining = cur_time_secs % self.interval;
        log::debug!("interval_remaining: {interval_remaining}");

        Ok(interval_remaining)
    }

    pub fn ensure_state_dir(&self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Entering ensure_state_dir");
        log::debug!("state_dir: {}", self.state_dir.display());

        if !Path::new(&self.state_dir).is_dir() {
            log::debug!("creating state directory");
            fs::create_dir(self.state_dir.clone())?;
        } else {
            log::debug!("state directory already exists");
        };

        Ok(())
    }

    pub fn update_state(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
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
            self.read_state()?
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
        };

        // Check if timestamp expired
        if cur_time_secs > knock_state.timestamp + self.interval {
            log::debug!("timestamp expired");
            changed = true;

            knock_state.config_digest = config_digest;
            knock_state.counter = 0;
            knock_state.timestamp = cur_time_secs - (cur_time_secs % self.interval);
        };

        if self.counter > knock_state.counter {
            log::debug!("counter incremented");
            changed = true;

            knock_state.counter = self.counter;
        };

        log::trace!("knock_state (after): {knock_state:?}");
        log::trace!("changed (after): {changed}");

        if changed {
            self.counter = knock_state.counter;
            self.timestamp = knock_state.timestamp;
            self.write_state(knock_state.clone())?;
        };

        log::debug!("knock_state: {knock_state:?}");
        log::debug!("changed: {changed}");
        log::debug!("self.count: {}", self.counter);
        log::debug!("self.timestamp: {}", self.timestamp);

        Ok(changed)
    }

    fn read_state(&self) -> Result<KnockState, Box<dyn std::error::Error>> {
        log::info!("Entering read_state");
        let state_file_path: PathBuf = Path::new(&self.state_dir).join(STATE_FILE_NAME);

        log::debug!("state_file_path: {}", state_file_path.display());
        let state_file_contents = fs::read(state_file_path)?;
        let state_file_string = str::from_utf8(&state_file_contents)?;

        let knock_state: KnockState = serde_json::from_str(state_file_string)?;
        log::debug!("knock_state: {knock_state:?}");

        Ok(knock_state)
    }

    fn write_state(&self, knock_state: KnockState) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Entering write_state");

        let state_file_path: PathBuf = Path::new(&self.state_dir).join(STATE_FILE_NAME);
        
        log::debug!("state_file_path: {}", state_file_path.display());
        log::debug!("knock_state: {knock_state:?}");

        fs::write(state_file_path, serde_json::ser::to_string(&knock_state)?)?;

        Ok(())
    }
}