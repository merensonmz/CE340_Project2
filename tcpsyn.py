from scapy.all import *
from scapy.layers.inet import TCP
from scapy.layers.inet import IP

def send_custom_syn_packet(src_ip, dst_ip, dst_port):
    # Create custom TCP SYN packet
    packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags='S')
    # Send the packet and receive the response
    response = sr1(packet, timeout=1)
    return response

def main():
    src_ip = "192.168.43.50"  # Replace with the source IP
    dst_ip = "192.168.43.174"  # Replace with the destination IP
    dst_port = 80  # Replace with the destination port

    print(f"Sending SYN packet from {src_ip} to {dst_ip} on port {dst_port}")

    response = send_custom_syn_packet(src_ip, dst_ip, dst_port)

    if response:
        response.show()
        print(f"Received response from {dst_ip} on port {dst_port}")
    else:
        print(f"No response from {dst_ip} on port {dst_port}")

if __name__ == "__main__":
    main()
