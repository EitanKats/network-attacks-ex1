import threading
import time
import uuid

from scapy.all import *
from scapy.layers.dot11 import Dot11Deauth, Dot11

# check if the user is root
if not os.geteuid() == 0:
    sys.exit("Please run as root")

mac_ap_mapping = {}
interface = sys.argv[1]
my_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 8 * 6, 8)][::-1])
# wifi_bssid = run(f"iwconfig {interface} | grep \"Access Point:\"", capture_output=True, shell=True, text=True).stdout.split()[5][-1]

under_attack = 0


# if not wifi_bssid:
#     print("No wifi bssid found")
#     sys.exit(1)

def simple_compute():
    # compute if my mac is under attack
    # by checking intervals between deauth packets and more
    # if it is under attack, ingore it in kernel level with iptables
    # and check if the attacker is still trying to attack, if not - remove the iptables rule

    while True:
        for ap_key, ap_clients in mac_ap_mapping.items():
            for client, deauth_timestamps in ap_clients.items():
                if len(deauth_timestamps) > 50:
                    if deauth_timestamps[-1] - deauth_timestamps[0] < 5:
                        print(f"the client {client} is under attack on {ap_key}")
                        # run(f"iptables -A OUTPUT -m mac --mac-source {my_mac} -j DROP", shell=True)
                    if deauth_timestamps[-1] - deauth_timestamps[0] > 5:
                        # run(f"iptables -D OUTPUT -m mac --mac-source {my_mac} -j DROP", shell=True)\
                        print(f"the client {client} no is longer under attack on {ap_key}")
                time.sleep(0.5)


def sniffReq(p):
    if p.haslayer(Dot11Deauth):
        client = p[Dot11].addr1
        ap = p[Dot11].addr2
        if not mac_ap_mapping.get(ap):
            mac_ap_mapping[ap] = {}
        if not mac_ap_mapping[ap].get(client):
            mac_ap_mapping[ap][client] = []

        attack_timestamps = mac_ap_mapping[ap][client]

        if len(attack_timestamps) > 50:
            attack_timestamps.pop(0)
        attack_timestamps.append(time.time())

        details = p.sprintf("new attacked AP [%Dot11.addr2%], Client[%Dot11.addr1%],Reason [%Dot11Deauth.reason%]")
        print(details)


threading.Thread(target=simple_compute).start()
sniff(iface=interface, prn=sniffReq)
