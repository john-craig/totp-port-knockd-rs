use std::str;
use iptables;
use regex::Regex;

const TRAFFIC_FILTER: &str = "totp-knockd-traffic";
const INPUT_FILTER: &str = "totp-knockd-input";
const SEQUENCE: &str = "totp-knockd-seq";

pub fn setup_port_knocking(dport: u32, kports: Vec<u32>) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Entering setup_port_knocking");
    let ipt = iptables::new(false)?;

    // Set up the main knocking filter chain and chains for each
    // knock in the sequence
    log::debug!("Adding new chain '{TRAFFIC_FILTER}' to table 'filter'");
    ipt.new_chain("filter", &format!("{TRAFFIC_FILTER}"))?;

    for i in 0..kports.len() {
        log::debug!("Adding new chain '{INPUT_FILTER}{i}' to table 'filter'");
        ipt.new_chain("filter", &format!("{INPUT_FILTER}{i}"))?;
    };
    
    let mut rule: String;

    rule = format!("-j {TRAFFIC_FILTER}");
    log::debug!("Appending rule '{rule}' to chain 'INPUT' in table 'filter'");
    ipt.append("filter", "INPUT", &rule)?;

    rule = "-m state --state ESTABLISHED,RELATED -j ACCEPT".to_string();
    log::debug!("Appending rule '{rule}' to chain '{TRAFFIC_FILTER}' in table 'filter'");
    ipt.append("filter", TRAFFIC_FILTER, &rule)?;

    /*
        Set up the final jump in the sequence. This allows a new connection to be established
        with the TCP protocol on the port `dport` when source IP of the connection has been
        added to the list `totp-knockd-seqX` in the past 30 seconds 
    */
    rule = format!("-m state --state NEW -m tcp -p tcp --dport {dport} \
        -m recent --rcheck --seconds 30 --name {SEQUENCE}{} \
        -j ACCEPT", 
        kports.len() - 1);
    log::debug!("Appending rule '{rule}' to chain '{TRAFFIC_FILTER}' in table 'filter'");
    ipt.append("filter", TRAFFIC_FILTER, &rule)?;

    // This rule has the same criteria as above, but it logs the event
    rule = format!("-m state --state NEW -m tcp -p tcp --dport {dport} \
        -m recent --rcheck --seconds 30 --name {SEQUENCE}{} \
        -j LOG --log-prefix '[totp-knockd-log] '", 
        kports.len() - 1);
    log::debug!("Appending rule '{rule}' to chain '{TRAFFIC_FILTER}' in table 'filter'");
    ipt.append("filter", TRAFFIC_FILTER, &rule)?;

    /*
        This rule drops any packets or connections which meet the criteria of the rule above
        but do not actually connect to the `dport` with TCP (e.g., they try to connect
        to a different port or use UDP for some reason)
    */
    rule = format!("-m state --state NEW -m tcp -p tcp --dport {dport} \
        -m recent --name {SEQUENCE}{} \
        --remove -j DROP", 
        kports.len() - 1);
    log::debug!("Appending rule '{rule}' to chain '{TRAFFIC_FILTER}' in table 'filter'");
    ipt.append("filter", TRAFFIC_FILTER, &rule)?;

    // Set up rules for each jump in the sequence in reverse order, starting from the second-to-last and con
    for i in (1..kports.len()).rev() {
        if i != 0 {
            /*
                The criteria for this rule is as follows:
                  - the protocol is TCP
                  - the destination port is equal to the port for this knock in the sequence
                  - the source IP of the connection was recently added to the list `totp-knockd-seqY`
                    which corresponds to the previous knock in the sequence
                The result of meeting all of these criteria is that the connection is jumped to
                the input filter for this knock in the sequence
            */
            rule = format!("-m state --state NEW -m tcp -p tcp --dport {} \
                -m recent --rcheck --name {SEQUENCE}{} \
                -j {INPUT_FILTER}{i}", 
                kports[i], i - 1);
            log::debug!("Appending rule '{rule}' to chain '{TRAFFIC_FILTER}' in table 'filter'");
            ipt.append("filter", TRAFFIC_FILTER, &rule)?;
            
            // Same criteria as above, but it logs event
            rule = format!("-m state --state NEW -m tcp -p tcp --dport {} \
                -m recent --rcheck --name {SEQUENCE}{} \
                -j LOG --log-prefix '[totp-knockd-log] '", 
                kports[i], i - 1);
            log::debug!("Appending rule '{rule}' to chain '{TRAFFIC_FILTER}' in table 'filter'");
            ipt.append("filter", TRAFFIC_FILTER, &rule)?;
            
            /*
                This rule has the same criteria but drops the packet if it was not sent 
                the correct port
            */
            rule = format!("-m state --state NEW -m tcp -p tcp \
                -m recent --name {SEQUENCE}{} \
                --remove -j DROP", 
                i - 1);
            log::debug!("Appending rule '{rule}' to chain '{TRAFFIC_FILTER}' in table 'filter'");
            ipt.append("filter", TRAFFIC_FILTER, &rule)?;

            /*
                The criteria for this rule is as follows:
                    - a packet has recently been jumped to the input filter for this knock in the sequence
                When this criteria is met, the following occurs:
                    - the source IP of the packet is added to the list `totp-knockd-seqX`
                      which corresponds to the current knock in the sequence
                    - the packet is dropped
            */
            rule = format!("-m recent --name {SEQUENCE}{i} \
                --set -j DROP");
            log::debug!("Appending rule '{rule}' to chain '{INPUT_FILTER}{i}' in table 'filter'");
            ipt.append("filter", &format!("{INPUT_FILTER}{i}"), &rule)?;
        } else {
            /*
                For the first port in the sequence there is not preceding list for
                a knock to be checked against. Instead, we create a rule with
                the following criteria:
                - the protocol is TCP
                - the destination port is equal to the port for the first knock in the sequence
                
                When these criteria are met, the packet is added to the list `totp-knockd-seq0`,
                which corresponds to the first knock in the sequence, and the packet is dropped.
            */
            rule = format!("-m state --state NEW -m tcp -p tcp --dport {} \
                -m recent --name {SEQUENCE}{i} \
                --set -j DROP", kports[i]);
            log::debug!("Appending rule '{rule}' to chain '{TRAFFIC_FILTER}' in table 'filter'");
            ipt.append("filter", TRAFFIC_FILTER, &rule)?;
        };
    };

    // Finally, set a rule to drop all packets sent to the traffic filter that do not match other rules
    rule = "-j DROP".to_string();
    log::debug!("Appending rule '{rule}' to chain '{TRAFFIC_FILTER}' in table 'filter'");
    ipt.append("filter", TRAFFIC_FILTER , &rule)?;

    Ok(())
}

pub fn teardown_port_knocking(num_ports: u32) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Entering teardown_port_knocking");
    let ipt = iptables::new(false)?;

    let rule: String;

    // Flush and delete all rules and chains used for totp-knockd
    if ipt.exists("filter", "INPUT", &format!("-j {TRAFFIC_FILTER}"))? {
        rule = format!("-j {TRAFFIC_FILTER}");
        log::debug!("Deleting rule '{rule}' from chain 'INPUT' from table 'filter'");
        ipt.delete("filter", "INPUT", &rule)?;
    };

    if ipt.chain_exists("filter", &format!("{TRAFFIC_FILTER}"))? {
        log::debug!("Flushing chain '{TRAFFIC_FILTER}' in table 'filter'");
        ipt.flush_chain("filter", &format!("{TRAFFIC_FILTER}"))?;
    };

    for i in 0..num_ports {
        if ipt.chain_exists("filter", &format!("{INPUT_FILTER}{i}"))? {
            log::debug!("Flushing chain '{INPUT_FILTER}{i}' in table 'filter'");
            ipt.flush_chain("filter", &format!("{INPUT_FILTER}{i}"))?;

            log::debug!("Deleting chain '{INPUT_FILTER}{i}' from table 'filter'");
            ipt.delete_chain("filter", &format!("{INPUT_FILTER}{i}"))?;
        };
    };

    if ipt.chain_exists("filter", &format!("{TRAFFIC_FILTER}"))? {
        log::debug!("Deleting chain '{TRAFFIC_FILTER}' from table 'filter'");
        ipt.delete_chain("filter", &format!("{TRAFFIC_FILTER}"))?;
    };

    Ok(())
}

pub fn get_knock_completions() -> Result<i32, Box<dyn std::error::Error>> {
    log::info!("Entering get_knock_completions");
    let ipt = iptables::new(false)?;
    log::debug!("test!");
    
    let ipt_output = ipt.execute("filter", &format!("-nvL {TRAFFIC_FILTER}"))?;
    
    if ! ipt_output.status.success() {
        log::error!("Unable to get knocking completions");
        return Ok(0);
    };
    
    let ipt_stdout = str::from_utf8(&ipt_output.stdout)?;
    log::trace!("ipt_stdout: {ipt_stdout}");
    
    // Define a regex pattern to match the line with ACCEPT target and extract the packet count
    let re = Regex::new(r"^\s*(\d+)\s+\d+\s+ACCEPT\s+.*$").unwrap();

    // Initialize a variable to store the number of packets matched by ACCEPT rule
    let mut num_completions = 0;

    // Iterate over each line of the output
    for line in ipt_stdout.lines() {
        if let Some(captures) = re.captures(line) {
            // The first capture group is the packet count
            if let Some(matched) = captures.get(1) {
                num_completions = matched.as_str().parse::<i32>().unwrap();
                break; // Exit the loop after finding the first ACCEPT rule
            }
        }
    }

    log::debug!("num_completions: {num_completions}");

    Ok(num_completions)
}