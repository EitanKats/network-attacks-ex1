#!/bin/bash

print_usage(){
    echo "Usage: sudo ./setup_run.sh --attack <attack_interface> --net <net_interface> --fake-ap <fake_ap_interface>"
    echo "Example: sudo ./setup_run.sh --attack wlan0 --net eth0 --fake-ap wlan1"
}

while [ "$1" != "" ]; do
    case $1 in
        --attack )              shift
                                ATTACK_INTERFACE=$1
                                ;;
        --net )                 shift
                                NET_INTERFACE=$1
                                ;;
        --fake-ap )   shift
                                FAKE_AP_INTERFACE=$1
                                ;;
    esac
    shift
done

if [ -z "$FAKE_AP_INTERFACE" ] || [ -z "$NET_INTERFACE" ] || [ -z "$ATTACK_INTERFACE" ]; then
    print_usage
    exit 1
fi

# check if we runing as sudo
if [ "$EUID" -ne 0 ] ; then
  echo "Please run as root"
  exit 1
fi

apt install build-essential zlib1g-dev hostapd isc-dhcp-server libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev wget nodejs python3 -y > /dev/null 2>&1
npm install > /dev/null 2>&1

service NetworkManager start
NET_IP=$(ifconfig $NET_INTERFACE | grep 'inet ' | awk '{print $2}')

if [ -z "$NET_IP" ]; then
    echo "Could not find IP for $NET_INTERFACE"
    exit 1
fi

export NET_IP ATTACK_INTERFACE NET_INTERFACE FAKE_AP_INTERFACE

sudo service NetworkManager stop
service hostapd stop # for the attack to scan only valid APs
pkill node # incase the node server is already runing
service isc-dhcp-server stop
sudo rfkill unblock wifi; sudo rfkill unblock all; sudo ifconfig $ATTACK_INTERFACE up # incase the interface is blocked by rfkill
sudo ifconfig $ATTACK_INTERFACE down
sudo iwconfig $ATTACK_INTERFACE mode monitor
sudo ifconfig $ATTACK_INTERFACE up

set -e errexit
source ./venv/bin/activate
./venv/bin/python3 scanner.py