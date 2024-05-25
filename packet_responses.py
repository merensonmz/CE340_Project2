from scapy.all import *
from scapy.layers.inet import TCP, ICMP, IP
import logging

logging.basicConfig(filename='packet_responses.log', level=logging.INFO, format='%(asctime)s %(message)s')

def send_ping(destination_ip):
    packet = IP(dst=destination_ip) / ICMP()
    response = sr1(packet, timeout=2)
    if response:
        logging.info(f"Ping response from {destination_ip}: {response.summary()}")
    return response

def send_custom_syn_packet(src_ip, dst_ip, dst_port):
    packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags='S')
    response = sr1(packet, timeout=2)
    if response:
        logging.info(f"SYN response from {dst_ip} on port {dst_port}: {response.summary()}")
    return response

def main():
    # Part 1: Send ICMP Echo Request
    destination_ip = "192.168.43.174"
    ping_response = send_ping(destination_ip)
    if ping_response:
        ping_response.show()
    else:
        print(f"No response from {destination_ip}")

    # Part 2: Send Custom TCP SYN Packet
    src_ip = "192.168.43.50"
    dst_port = 80
    syn_response = send_custom_syn_packet(src_ip, destination_ip, dst_port)
    if syn_response:
        syn_response.show()
    else:
        print(f"No response from {destination_ip} on port {dst_port}")

if __name__ == "__main__":
    main()
