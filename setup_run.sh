
# set -e errexit

while [ "$1" != "" ]; do
    case $1 in
        --attack )              shift
                                ATTACK_INTERFACE=$1
                                ;;
    esac
    shift
done

# check if we runing as sudo
if [ "$EUID" -ne 0 ] ; then
  echo "Please run as root"
  exit 1
fi

export ATTACK_INTERFACE

apt install build-essential zlib1g-dev hostapd isc-dhcp-server libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev wget nodejs python3 -y > /dev/null 2>&1
npm install > /dev/null 2>&1

sudo service NetworkManager stop
service hostapd stop # for the attack to scan only valid APs
service isc-dhcp-server stop
sudo rfkill unblock wifi; sudo rfkill unblock all; sudo ifconfig $ATTACK_INTERFACE up # incase the interface is blocked by rfkill
sudo ifconfig $ATTACK_INTERFACE down
sudo iwconfig $ATTACK_INTERFACE mode monitor
sudo ifconfig $ATTACK_INTERFACE up

set -e errexit

source venv/bin/activate
./venv/bin/python3 scanner.py