use psocket::{TcpSocket, IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

pub fn knock_ports(ip_address: Ipv4Addr, dest_port: u32, kports: Vec<u32>) -> bool {
    log::info!("Entering knock_ports");
    let mut success = false;

    for i in 0..kports.len() {
        let p_num = kports[i];

        log::debug!("knocking port: {p_num}");
        let _ = TcpSocket::connect(&SocketAddr::new(IpAddr::V4(ip_address), p_num.try_into().unwrap()));
    }

    log::debug!("knocking port dest_port: {dest_port}");
    if let Ok(_) = TcpSocket::connect(&SocketAddr::new(IpAddr::V4(ip_address), dest_port.try_into().unwrap())) {
        success = true;
    }

    log::debug!("success: {success}");
    success
}