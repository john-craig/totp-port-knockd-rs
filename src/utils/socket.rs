use psocket::{IpAddr, Ipv4Addr, SocketAddr, TcpSocket};
use std::thread;
use std::time::Duration;

const KNOCK_CONNECT_TIMEOUT_MS: u64 = 250;
const KNOCK_INTER_DELAY_MS: u64 = 400;
const DEST_CONNECT_TIMEOUT_SECS: u64 = 3;
const DEST_SETTLE_DELAY_MS: u64 = 500;

pub fn knock_ports(
    ip_address: Ipv4Addr,
    dest_port: u32,
    kports: Vec<u32>,
) -> Result<bool, Box<dyn std::error::Error>> {
    log::info!("Entering knock_ports");
    let mut success = false;

    for i in 0..kports.len() {
        let p_num = kports[i];

        log::debug!("knocking port: {p_num}");
        let knock_addr = SocketAddr::new(IpAddr::V4(ip_address), p_num.try_into()?);
        let _ = TcpSocket::connect_timeout(
            &knock_addr,
            Duration::from_millis(KNOCK_CONNECT_TIMEOUT_MS),
        )
        .map(|sock| {
            sock.close();
        });

        // Give the remote firewall time to observe and commit the recent-list
        // state for this knock before sending the next one.
        thread::sleep(Duration::from_millis(KNOCK_INTER_DELAY_MS));
    }

    log::debug!("knocking port dest_port: {dest_port}");
    thread::sleep(Duration::from_millis(DEST_SETTLE_DELAY_MS));

    match TcpSocket::connect_timeout(
        &SocketAddr::new(IpAddr::V4(ip_address), dest_port.try_into()?),
        Duration::from_secs(DEST_CONNECT_TIMEOUT_SECS),
    ) {
        Ok(sock) => {
            sock.close();
            success = true;
        }
        Err(err) => {
            log::error!("Error connecting to destination port: {:?}", err);
        }
    };

    log::debug!("success: {success}");
    Ok(success)
}
