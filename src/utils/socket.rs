use psocket::{IpAddr, Ipv4Addr, SocketAddr, TcpSocket};
use std::thread;
use std::time::Duration;

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
        let _ = TcpSocket::connect_timeout(&knock_addr, Duration::from_millis(100)).map(|sock| {
            sock.close();
        });
        thread::sleep(Duration::from_millis(200));
    }

    log::debug!("knocking port dest_port: {dest_port}");
    match TcpSocket::connect_timeout(
        &SocketAddr::new(IpAddr::V4(ip_address), dest_port.try_into()?),
        Duration::from_secs(2),
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
