use simple_logger::SimpleLogger;
use which::which;
use std::thread;
use std::time::Duration;
use fork::{fork, Fork};
use nix::unistd::Pid;
use nix::sys::signal::{self, Signal};
use signal_hook::{consts::SIGINT, consts::SIGTERM, iterator::Signals};

#[path = "../utils/kports.rs"] mod kports;
#[path = "../utils/iptables.rs"] mod iptables;
#[path = "../utils/config.rs"] mod config;

fn main() {    
    SimpleLogger::new().init().unwrap();
    
    let knock_daemon: config::KnockDaemon = config::build_knock_daemon();

    // Ensure `iptables` is available in the current PATH
    which("iptables").unwrap();

    // Create the state directory if it does not already exist
    knock_daemon.ensure_state_dir();
    
    match knock_daemon.action {
        config::DaemonActionKind::Start => start_daemon(knock_daemon),
        config::DaemonActionKind::Stop => stop_daemon(knock_daemon),
    }
}

fn start_daemon(knock_daemon: config::KnockDaemon) {
    log::info!("Entering start_daemon");
    match fork() {
        Ok(Fork::Parent(pid)) => {
            knock_daemon.save_pid(pid)
        }
        Ok(Fork::Child) => {
            run_daemon(knock_daemon)
        },
        Err(_) => {
            log::error!("Forking daemon failed");
        },
     }
}

fn stop_daemon(knock_daemon: config::KnockDaemon) {
    log::info!("Entering stop_daemon");
    let daemon_pid: i32 = knock_daemon.read_pid();

    log::debug!("daemon_pid: {daemon_pid}");
    signal::kill(Pid::from_raw(daemon_pid), Signal::SIGTERM).unwrap();

    // Exit the process
    std::process::exit(0);
}

fn run_daemon(mut knock_daemon: config::KnockDaemon) {
    log::info!("Entering run_daemon");
    let mut signals = Signals::new([SIGINT, SIGTERM]).unwrap();

    log::debug!("spawning signal processing thread");
    let kd_signal_clone = knock_daemon.clone();
    thread::spawn(move || {
        for _ in signals.forever() {
            log::info!("Recieved termination or interrupt signal");

            // Teardown all the rules
            iptables::teardown_port_knocking(kd_signal_clone.num_ports);

            // Delete the PID file
            kd_signal_clone.clean_pid();

            // Exit the process
            std::process::exit(0);
        }
    });

    loop {
        // Update the state of the knock daemon
        let expired: bool = knock_daemon.update_state();

        if expired {
            log::debug!("rebuilding knock rules");

            // Teardown the port knocking rules. This will have
            // no negative effects if they were not set up previously.
            iptables::teardown_port_knocking(knock_daemon.num_ports);

            // Generate new ports
            let kport_values: Vec<u32> = kports::calculate_kports(
                knock_daemon.secret_value.clone().into(),
                knock_daemon.interval,
                knock_daemon.counter,
                knock_daemon.num_ports,
                knock_daemon.port_range.clone());
            log::trace!("kport_values: {:?}", kport_values);

            iptables::setup_port_knocking(knock_daemon.dest_port, kport_values);
        }

        // Get number of seconds remaining in this interval
        let interval_remaining = knock_daemon.interval_remaining();
        log::debug!("interval_remaining: {interval_remaining}");

        for _ in 0..interval_remaining {
            thread::sleep(Duration::from_secs(1));

            if iptables::get_knock_completions() > 0 {
                log::debug!("incrementing knock counter");

                knock_daemon.counter += 1;
                break;
            }
        }
    }
}