use hmac::{Mac, SimpleHmac};
use sha2::Sha512;
use std::time::{SystemTime, UNIX_EPOCH};

const SHA512_OCTETS: u32 = 64;
const OCTET_BITS: u32 = 8;
const MAX_PORT_NUM: u32 = 65535;

type HmacSha512 = SimpleHmac<Sha512>;

#[allow(dead_code)]
pub fn calculate_kports(
    totp_secret: Vec<u8>,
    totp_interval: u64,
    totp_counter: u32,
    num_ports: u32,
    port_range: Vec<u32>,
) -> Vec<u32> {
    // Get the current Unix timestamp
    let cur_time_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Get the timestamp as of the start of this interval
    let timestamp = cur_time_secs - (cur_time_secs % totp_interval);
    calculate_kports_for_timestamp(totp_secret, timestamp, totp_counter, num_ports, port_range)
}

pub fn calculate_kports_for_timestamp(
    totp_secret: Vec<u8>,
    timestamp: u64,
    totp_counter: u32,
    num_ports: u32,
    port_range: Vec<u32>,
) -> Vec<u32> {
    log::info!("Entering calculate_kports");
    // Validate inputs
    assert!(port_range.len() == 2);
    assert!(port_range[1] <= MAX_PORT_NUM);
    assert!(port_range[0] < port_range[1]);

    // Calculate number of bits required to express each
    // port number
    let port_bitwidth = (port_range[1] - port_range[0]).ilog2() + 1;

    // Make sure we can actually produce this many ports
    assert!(port_bitwidth * num_ports <= (SHA512_OCTETS * OCTET_BITS));
    log::debug!("port_bitwidth: {:?}", port_bitwidth);
    log::debug!("timestamp: {:?}", timestamp);

    // Set up HMAC
    let mut hmac_buf: Vec<u8>;
    let mut totp_hmac = HmacSha512::new_from_slice(&totp_secret).unwrap();

    totp_hmac.update(&(timestamp.to_ne_bytes()));

    // If necessary, iterate the HMAC operation
    for _ in 0..totp_counter {
        hmac_buf = totp_hmac.clone().finalize().into_bytes().to_vec();

        totp_hmac.update(&hmac_buf);
    }

    // Perform final HMAC operation and reset hasher
    hmac_buf = totp_hmac.finalize().into_bytes().to_vec();
    log::debug!("{:02X?}", hmac_buf);

    let mut kports = Vec::new();

    let m_bytes: u32 = port_bitwidth / OCTET_BITS;
    let mod_bits: u32 = port_bitwidth % OCTET_BITS;

    let mut c_byte: usize;
    let mut l_bits: u32;
    let mut r_bits: u32;
    let mut p_num: u32;

    c_byte = 0;
    r_bits = 0;

    for i in 0..num_ports {
        log::trace!("Generating port number {:?}", i);
        p_num = 0;

        l_bits = (OCTET_BITS - r_bits) % OCTET_BITS;
        r_bits = (mod_bits - l_bits) % OCTET_BITS;

        log::trace!("   m_bytes: {:?}", m_bytes);
        log::trace!("   l_bits: {:?}", l_bits);
        log::trace!("   r_bits: {:?}", r_bits);

        if l_bits != 0 {
            p_num +=
                u32::from((hmac_buf[c_byte] << (OCTET_BITS - l_bits)) >> (OCTET_BITS - l_bits));
            c_byte += 1;
        }

        for _ in 0..m_bytes {
            p_num = p_num << OCTET_BITS;
            p_num += u32::from(hmac_buf[c_byte]);
            c_byte += 1;
        }

        if r_bits != 0 {
            p_num = p_num << r_bits;
            p_num += u32::from(hmac_buf[c_byte] >> (OCTET_BITS - r_bits));
        }

        p_num = p_num + port_range[0];
        log::trace!("   p_num: '{:X}'X, {:?}", p_num, p_num);

        kports.push(p_num);
    }

    return kports;
}
