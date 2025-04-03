#!/bin/bash

# Check if the 'br0' interface exists and is up
if ip link show br0 | grep -q "state UP"; then
    echo "Bridge network already set up"
else
    echo "Setting up bridge network"
    # Create br0
    sudo ip link add br0 type bridge
    sudo ip link set br0 up

    # Add enp2s0 to br0
    sudo ip link set enp2s0 master br0
    sudo ip addr flush dev enp2s0

    # Configure br0
    sudo ip addr add 192.168.1.32/24 brd + dev br0
    sudo ip route add default via 192.168.1.1 dev br0

    # Create tap0 and add to br0
    sudo ip tuntap add dev tap0 mode tap user $(whoami)
    sudo ip addr flush dev tap0
    sudo ip link set dev tap0 up
    sudo ip link set tap0 master br0
fi

pushd $VIRTUAL_MACHINE_CONFIGURATIONS
    # Build the test-vm for the current run
    build-machine test-vm

    # Run the test VM
    result/bin/run-nixos-vm
popd