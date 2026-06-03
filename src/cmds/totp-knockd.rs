use clap::Parser;
use log::LevelFilter;
use signal_hook::{consts::SIGINT, consts::SIGTERM, iterator::Signals};
use simple_logger::SimpleLogger;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use which::which;

#[path = "../utils/iptables.rs"]
mod iptables;
#[path = "../utils/kports.rs"]
mod kports;
#[path = "../utils/options.rs"]
mod options;

fn main() {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .env()
        .init()
        .unwrap();

    // Ensure `iptables` is available in the current PATH
    match which("iptables") {
        Ok(_) => {}
        Err(err) => {
            log::error!("Error locating iptables: {:?}", err);
            std::process::exit(1);
        }
    };

    let knock_daemon = match KnockDaemon::build_daemon() {
        Ok(kd) => kd,
        Err(err) => {
            log::error!("Error preparing configuration: {:?}", err);
            std::process::exit(1);
        }
    };

    // Create the state directory if it does not already exist
    match knock_daemon.ensure_state_dir() {
        Ok(_) => {}
        Err(err) => {
            log::error!("Error ensuring state directory: {:?}", err);
            std::process::exit(1);
        }
    };

    match run_daemon(knock_daemon) {
        Ok(_) => {}
        Err(err) => {
            log::error!("Error running daemon: {:?}", err);
        }
    };

    // Exit the process
    std::process::exit(0);
}

fn run_daemon(mut knock_daemon: KnockDaemon) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Entering run_daemon");
    let mut signals = Signals::new([SIGINT, SIGTERM])?;

    log::debug!("spawning signal processing thread");
    let (send_shutdown, recv_shutdown) = mpsc::channel();
    let (send_acknowledge, recv_acknowledge) = mpsc::channel();
    let kd_signal_clone = knock_daemon.clone();
    let signal_thread = thread::spawn(move || {
        for _ in signals.forever() {
            log::info!("Recieved termination or interrupt signal");
            match send_shutdown.send(true) {
                Ok(_) => {
                    log::info!("Sent shutdown signal to main thread");
                }
                Err(err) => {
                    log::error!("Failed to send shutdown signal to main thread: {:?}", err);
                    std::process::exit(1);
                }
            };

            let _ = recv_acknowledge.recv();

            // Teardown all the rules
            match iptables::teardown_port_knocking(kd_signal_clone.knock_common.num_ports) {
                Ok(_) => log::info!("Final port knocking teardown successful"),
                Err(err) => log::error!("Error performing final port knocking teardown: {:?}", err),
            };

            // Delete the PID file
            let _ = kd_signal_clone.clean_pid();

            // Exit the signal loop so the main thread can join cleanly.
            break;
        }
    });

    loop {
        // Update the state of the knock daemon
        let expired: bool = knock_daemon.update_state()?;
        let mut shutdown: bool = false;

        if expired {
            log::debug!("rebuilding knock rules");

            // Teardown the port knocking rules. This will have
            // no negative effects if they were not set up previously.
            iptables::teardown_port_knocking(knock_daemon.knock_common.num_ports)?;

            // Generate new ports
            let kport_values: Vec<u32> = kports::calculate_kports(
                knock_daemon.knock_common.secret_value.clone().into(),
                knock_daemon.knock_common.interval,
                knock_daemon.knock_common.counter,
                knock_daemon.knock_common.num_ports,
                knock_daemon.knock_common.port_range.clone(),
            );
            log::trace!("kport_values: {:?}", kport_values);

            iptables::setup_port_knocking(knock_daemon.knock_common.dest_port, kport_values)?;
        };

        // Get number of seconds remaining in this interval
        let interval_remaining = knock_daemon.interval_remaining()?;
        log::debug!("interval_remaining: {interval_remaining}");

        for _ in 0..interval_remaining {
            shutdown = match recv_shutdown.try_recv() {
                Ok(msg) => msg,
                Err(_) => false,
            };
            if shutdown {
                break;
            };

            thread::sleep(Duration::from_secs(1));
            let accepted_packets: u32 =
                iptables::get_accepted_packets(knock_daemon.knock_common.dest_port)?;

            if accepted_packets > 0 {
                log::debug!("incrementing knock counter");
                knock_daemon.knock_common.counter += 1;
                break;
            };
        }

        if !shutdown {
            shutdown = match recv_shutdown.try_recv() {
                Ok(msg) => msg,
                Err(_) => false,
            };
        };

        if shutdown {
            log::info!("Recieved shutdown signal from signal handling thread");
            send_acknowledge
                .send(())
                .expect("Failed to send acknowledgement to signal handling thread");
            break;
        };
    }

    signal_thread
        .join()
        .expect("Failed to rejoin signal handling thread");
    Ok(())
}

/************************************************************************************/
/* Knock Daemon                                                                     */
/************************************************************************************/

const DAEMON_CONFIG_VAR_NAME: &str = "TOTP_KNOCKD_CONFIG_PATH";
const DAEMON_STATE_VAR_NAME: &str = "TOTP_KNOCKD_STATE_DIR";

const DAEMON_DEFAULT_CONFIG_PATH: &str = "/etc/totp-knockd/daemon.toml";
const DAEMON_DEFAULT_STATE_DIR: &str = "/var/lib/totp-knockd";

const PID_FILE_NAME: &str = "daemon.pid";

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
}

#[derive(Clone, Debug)]
pub struct KnockDaemon {
    pub knock_common: options::KnockCommon,
}

impl KnockDaemon {
    pub fn build_daemon() -> Result<KnockDaemon, Box<dyn std::error::Error>> {
        log::info!("Entering build_daemon");
        let args = DaemonArgs::parse();

        // Determine configuration file path based on env var
        let config_path_string: String = match env::var(DAEMON_CONFIG_VAR_NAME) {
            Ok(val) => val,
            Err(_) => DAEMON_DEFAULT_CONFIG_PATH.to_string(),
        };
        log::debug!("config_path_string: {config_path_string}");
        let config_path: &Path = Path::new(&config_path_string);
        log::debug!("config_path: {}", config_path.display());

        // Determine state file path based on env var
        let state_dir_string: String = match env::var(DAEMON_STATE_VAR_NAME) {
            Ok(val) => val,
            Err(_) => DAEMON_DEFAULT_STATE_DIR.to_string(),
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

        Ok(KnockDaemon {
            knock_common: knock_common.clone(),
        })
    }

    pub fn interval_remaining(&self) -> Result<u64, Box<dyn std::error::Error>> {
        self.knock_common.interval_remaining()
    }

    pub fn ensure_state_dir(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.knock_common.ensure_state_dir()
    }

    pub fn save_pid(&self, pid: i32) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Entering save_pid");
        log::debug!("pid: {pid}");
        let pidfile_path: PathBuf = Path::new(&self.knock_common.state_dir).join(PID_FILE_NAME);

        log::debug!("pidfile_path: {}", pidfile_path.display());
        fs::write(pidfile_path, pid.to_string())?;

        Ok(())
    }

    pub fn read_pid(&self) -> Result<i32, Box<dyn std::error::Error>> {
        log::info!("Entering read_pid");
        let pidfile_path: PathBuf = Path::new(&self.knock_common.state_dir).join(PID_FILE_NAME);

        // Read pidfile and convert contents to i32
        log::debug!("pidfile_path: {}", pidfile_path.display());
        let pidfile_contents = fs::read(pidfile_path)?;
        let pidfile_string = str::from_utf8(&pidfile_contents)?;

        let pid: i32 = pidfile_string.parse()?;

        log::debug!("pid: {pid}");
        Ok(pid)
    }

    pub fn clean_pid(&self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Entering clean_pid");
        let pidfile_path: PathBuf = Path::new(&self.knock_common.state_dir).join(PID_FILE_NAME);

        log::debug!("pidfile_path: {}", pidfile_path.display());
        fs::remove_file(pidfile_path)?;

        Ok(())
    }

    pub fn update_state(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        self.knock_common.update_state()
    }
}
