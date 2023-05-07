import sys
from scapy.layers.dot11 import Dot11Deauth, Dot11
from scapy.all import *
import uuid
import time
import threading
from subprocess import run

# check if the user is root
if not os.geteuid() == 0:
    sys.exit("Please run as root")

interface = sys.argv[1]
deauth_time = []
my_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,8*6,8)][::-1])
wifi_bssid = run(f"iwconfig {interface} | grep \"Access Point:\"", capture_output=True, shell=True, text=True).stdout.split()[5][-1]

if not wifi_bssid:
    print("No wifi bssid found")
    sys.exit(1)

def simple_comute():
    # comute if my mac is under attack 
    # by checking intervals between deauth packets and more
    # if it is under attack, ingore it in kernel level with iptables
    # and check if the attacker is still trying to attack, if not - remove the iptables rule
    pass

def sniffReq(p):
    if p.haslayer(Dot11Deauth):
        client = p[Dot11].addr1
        ap = p[Dot11].addr2
        if client == my_mac and wifi_bssid == ap:
            deauth_time.append(time.time())
        details = p.sprintf("new attacked AP [%Dot11.addr2%], Client[%Dot11.addr1%],Reason [%Dot11Deauth.reason%]")
        print (details)
        
            


threading.Thread(target=simple_comute).start()
sniff(iface=interface,prn=sniffReq)