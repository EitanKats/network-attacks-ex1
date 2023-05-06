

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
fi > /dev/null 2>&1

export ATTACK_INTERFACE

echo "check if we have all the dependencies"
apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev wget nodejs python3 -y > /dev/null 2>&1


service NetworkManager stop	
ifconfig $ATTACK_INTERFACE down
iwconfig $ATTACK_INTERFACE mode monitor
sudo ifconfig $ATTACK_INTERFACE up

echo "interface $ATTACK_INTERFACE is ready for attack"

source venv/bin/activate
./venv/bin/python3 scanner.py