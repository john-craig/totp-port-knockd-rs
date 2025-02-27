use simple_logger::SimpleLogger;

#[path = "../utils/kports.rs"] mod kports;
#[path = "../utils/socket.rs"] mod socket;
#[path = "../utils/config.rs"] mod config;

fn main() {    
    SimpleLogger::new().init().unwrap();

    let mut knocker: config::Knocker = config::build_knocker();

    // Create the state directory if it does not already exist
    knocker.ensure_state_dir();

    let mut success = false;

    while !success {
        log::debug!("attempting knock sequence");

        knocker.update_state();

        // Generate new ports
        let kport_values: Vec<u32> = kports::calculate_kports(
            knocker.secret_value.clone().into(),
            knocker.interval,
            knocker.counter,
            knocker.num_ports,
            knocker.port_range.clone());
        log::trace!("kport_values: {:?}", kport_values);

        // Attempt to knock the ports
        success = socket::knock_ports(
            knocker.ip_address,
            knocker.dest_port,
            kport_values);

        // Increment the counter
        knocker.counter += 1;
    }

    knocker.update_state();
}
