from scapy.all import *

# Hedef IP adresi
from scapy.all import IP  # Import the missing IP class

from scapy.all import ICMP  # Import the missing ICMP class

target_ip = "192.168.43.174"  # Kendi hedef IP adresinizi buraya yazın

# ICMP Echo Request paketi oluşturma
icmp_request = IP(dst=target_ip)/ICMP()

# Paketi gönderme ve yanıtı yakalama
response = sr1(icmp_request, timeout=2)

# Yanıtı kontrol etme ve çıktıyı yazdırma
if response:
    print("Responce received:")
    response.show()
else:
    print("Responce not received.")
