# totp-port-knockd-rs
A package for securing system with TOTP port knocking, written in Rust.

## Introduction
TOTP port knocking is a network security specialty that aims to address the reliance of traditional port knocking schemes on security-by-obscurity by deriving the knocking sequence required for opening a protected port from a time-based one-time passcode. This time-based one-time passcode is derived from a secret value which must be pre-shared between the server and client(s). For more information about the security of TOTP port knocking and recommended settings, see "Security" below.

## Usage
The `totp-port-knockd-rs` package includes separate binaries for the server (`totp-knockd`) and client (`totp-knocker`).

### Common
Both the `totp-knockd` server and `totp-knocker` client must recieve the following parameters from either command line options or their respective configuration file:
 - **secret_value**: The plaintext value of the shared secret to be used for deriving time-based one-time passcodes. Required, unless *secret_path* is specified instead. Mutually exclusive with *secret_path*.
 - **secret_path**: The path to a file containing the plaintext value of the shared secret to be used for deriving time-based ontime-passcodes. Required, unless *secret_value* is specified instead. Mutually exclusive with *secret_value*.
 - **time_interval**: The length of time-based one-time passcode interval, in seconds. Optional, default is 30 seconds.
 - **min_port**: The lower end of the range of ports which are used for the knocking sequence. Minimum value is 1, maximum value is 65534. Optional, default is 1024.
 - **max_port**: The upper end of the range of ports which are used for the knocking sequence. Minimum value is 2, maximum value is 65535. Optional, default is 23768.
 - **num_ports**: The number of ports to be used in the knocking sequence. Maximum and minimum values constrained by port range chosen by *min_port* and *max_port* values. Optional, default is 32.
 - **dest_port**: The destination port which is opened for connections when the knocking sequence is completed successfully. Required.

Parameters specified using command line options always take priority over parameters specified in the configuration file.

Both the server and client will use these parameters to construct a sequence of ports to be knocked in order for the destination port to be opened. The ports chosen by the knocking sequence will always fall within the range set by *min_port* and *max_port*, and the number of ports in the sequence will be of length *num_ports*.

The client and server must use the same port sequence (and thus, must have matching values for the above parameters) in order for a client to initiate a succesful connection.

### Server
The `totp-knockd` command accepts no arguments, but may accept one or more options corresponding to the common parameters specified above. It may also accept these parameters from a configuration file.

Once invoked, `totp-knockd` will calculate the knocking sequence for the current time interval based on the provided parameters, and then erect a series of firewall rules to implement this knocking sequence. When the time interval elapses, or a successful connection is made, `totp-knockd` will tear down the previous set of rules, then calculate and erect the next set. Upon recieving a SIGTERM or SIGINT, `totp-knockd` will clean up the current set of firewall rules and exit.

The `totp-knockd` command relies upon `iptables` in order to construct the rules necessary for the knocking sequence. An `iptables` binary must be available in the environment of the caller of `totp-knockd`, and the caller must have authority to execute `iptables` to create and modify firewall rules. 

**Configuration File**
The `totp-knockd` command will search for the server configuration file with the following order of priority:
    1) the path specified by the environment variable `$TOTP_KNOCKD_CONFIG_PATH`, if it set
    2) the path `/etc/totp-knockd/daemon.toml`

An example configuration file may be found at `extra/config.toml`.

**State File**
The `totp-knockd` command will create a state file to store the count of successful connections which have been made during a given time interval. The path chosen for the state file is based on the following order of priority:
    1) the path `$TOTP_KNOCKD_STATE_DIR/state.json`, if the `$TOTP_KNOCKD_STATE_DIR` environment variables is set
    2) the path `/var/lib/totp-knockd/state.json`

### Client
The `totp-knocker` command has no external dependencies. It accepts a single required argument, *IP_ADDRESS*, which must be the IP address of the host to be knocked.

**Configuration File**
The `totp-knocker` command will search for the client configuration file with the following order of priority:
    1) the path specified by the environment variable `$TOTP_KNOCKER_CONFIG_PATH`, if it set
    2) the path `$XDG_CONFIG_HOME/totp-knocker/knocker.toml`, if the `$XDG_CONFIG_HOME` environment variable is set
    3) the path `$HOME/.config/totp-knocker/knocker.toml`

An example configuration file may be found at `extra/config.toml`.

**State File**
The `totp-knocker` command will create a state file to store the count of successful connections between invocations. The path chosen for the state file is based on the following order of priority:
    1) the path `$TOTP_KNOCKER_STATE_DIR/state.json`, if the `$TOTP_KNOCKER_STATE_DIR` environment variables is set
    2) the path `$XDG_STATE_HOME/totp-knocker/state.json`, if the `$XDG_STATE_HOME` environment variable is set
    3) the path `$HOME/.local/state/totp-knocker/state.json`

## Security
### Algorithm
The TOTP algorithm used by `totp-port-knockd-rs` differs from that described by (RFC-6238)[https://www.rfc-editor.org/rfc/rfc6238] in that it computes HMAC-SHA-512(K,T) rather than HOTP(K,T). This is done to produce a much longer byte string of sixty-four octets which can be split up into the individual port numbers used in the knocking sequence.

The knocking sequence is calculated using the following steps:

    1) Determine the bitwidth required for each port:
        bitwidth = log2(max_port - min_port)
    2) Calculate the start of the current time interval, where *timestamp* is the current time in seconds:
        interval_start = timestamp - (timestamp % time_interval)
    3) Calculate the SHA-512 HMAC of the current time interval:
        hmac = HMAC-SHA-512(secret_value, interval_start)
    4) Iterate step 3 with the previous *hmac* value as input to the next HMAC-SHA-512 operators, up to *counter* times, 
    where *counter* is the number of successful connections that have made during this time interval:
        for i in counter
            hmac = HMAC-SHA-512(secret_value, hmac)
    5) Split the HMAC byte array into a sequence of port numbers
        sequence[0] = min_port + bitslice(hmac, 0, bitwidth)
        sequence[1] = min_port + bitslice(hmac, bitwidth+1, bitwidth*2)
        ...

The `bitslice` function used in step 3 selects a substring with start and end indices specified by the second and third parameter from a bitstring passed by the first parameter, and evaluates this substring as an unsigned integer.

This algorithm efficiently splits the result of the HMAC-SHA-512 into the maximum sequence length possible based on the range of port numbers chosen by the user. For example if the user choses a port range of \[0-255\], each port number would only require log2(256) = 8 bits, meaning the 512-bit HMAC value could be split into a sequence of 64 numbers.

### Replay Attacks and Multi-Client Support
One threat against port knocking of any kind are replay attacks. An attacker can observe the sequence of knocks sent by the client to the server and repeat them afterwards to trick the server into opening the protected port. The introduction of a TOTP mechanism does not remove this threat by itself, as an attacker still has a window of opportunity within the time interval of the TOTP to replay the knocking sequence.

`totp-port-knockd-rs` mitigates this threat by introducing a counter to its TOTP computation. Each time a successful connection is made, the counter is incremented, and a new TOTP computation is calculated by iterating the HMAC-SHA-512 operation an additional time. This means that a subsequent connection within the same time interval will require a different knocking sequence, and thus a replay attack is rendered ineffective.

However, this solution introducing its own problems. While a single client can keep track of how many successful connections it has made to a server, and thus correctly compute the knocking sequence for a subsequent connection within the same time interval, when multiple different clients connect to the same server there is no direct way for one client to be aware of the number of successful connections made by another.

The solution to the issue of multi-client counter desynchronization taken by `totp-port-knockd-rs` is  for a connecting client to assume that if its knocking sequence does not lead to a successful connection attempt, then its count is behind that of the server, and to continue retrying the sequence and incrementing its count until it catches up. 