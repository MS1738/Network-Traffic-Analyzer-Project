from scapy.all import *
from scapy.layers.inet import IP, TCP
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
import numpy as np
from behaviour import get_cluster_centers



packet_counter = 0  # Global variable to store the packet counter
packet_sizes = []    # List to store packet sizes for visualization
malicious_domains = [] # malicious domain names

cluster_centers = get_cluster_centers()

def process_packet(packet):
    global packet_counter  # Use the global packet_counter variable
    packet_counter += 1  # Increment the packet counter

    if IP in packet:            # 1. Packet Capture and Analysis - TCP header
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_size = len(packet)
        packet_sizes.append(packet_size)  # Add packet size to the list for visualization

        # Print packet number, advanced packet information, and packet size
        print(f"Packet #{packet_counter}: IP Source: {ip_src} --> IP Destination: {ip_dst}")
        print(f"Packet #{packet_counter}: Packet Size: {packet_size} bytes")


        if packet_size > np.max(cluster_centers):
            print(f"\033[91mPacket #{packet_counter}: Anomaly detected - Packet size above maximum cluster center ({np.max(cluster_centers)} bytes)\033[0m")

        # 2. Protocol Decoding
        # Check for unusual TCP ports
        if packet.haslayer(TCP) and packet[TCP].dport not in [80, 443, 22]:
            print(f"Packet #{packet_counter}: Potential malicious activity - Unusual TCP port (Source: {ip_src}, Destination: {ip_dst}, Port: {packet[TCP].dport})")
            
        # Detect HTTP packets
        if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].dport == 443):
            print(f"Packet #{packet_counter}: HTTP/HTTPS packet detected")    

        # Check for unusually high packet rate
        threshold = 500  # Adjust the threshold as needed
        if len(packet) > threshold:
            print(f"Packet #{packet_counter}: Potential malicious activity - High packet rate")
            
            
        # Read the list of malicious domain names or IP addresses from a file
        file_path = "C:/Users/Maulik Suryavanshi/VSCode Projects/Python/Network Traffic Analyzer/Network-Traffic-Analyzer-Project/malicious_domains.txt"
        with open(file_path, "r") as file:
            malicious_domains = [line.strip() for line in file]

        # if the packet has the domain from that list, flag that packet as malicious
        if packet.haslayer(DNS) and packet[DNS].qd is not None and str(packet[DNS].qd.qname, 'utf-8') in malicious_domains:
            print(f"Packet #{packet_counter}: Potential malicious activity - Detected suspicious DNS request")    





        # Check payload for known malicious signatures
        # if packet.haslayer(Raw) and "malicious_string" in str(packet[Raw].load): # replace malicious_string
        #     print(f"Packet #{packet_counter}: Potential malicious activity - Detected malicious payload")


# Sniff packets and process them
sniff(iface="Ethernet", prn=process_packet, store=False, timeout=10) # adjust timeout for how long we want it to run for

# 3. Traffic Monitoring and Visualization
# Visualization - very minimal for now
plt.plot(packet_sizes)
plt.xlabel("Packet Number")
plt.ylabel("Packet Size (bytes)")
plt.title("Packet Sizes over Time")
plt.show()
