from scapy.all import *
import matplotlib.pyplot as plt

packet_counter = 0  # Global variable to store the packet counter
packet_sizes = []    # List to store packet sizes for visualization

def process_packet(packet):
    global packet_counter  # Use the global packet_counter variable
    packet_counter += 1  # Increment the packet counter

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_size = len(packet)
        packet_sizes.append(packet_size)  # Add packet size to the list for visualization

        # Print packet number, advanced packet information, and packet size
        print(f"Packet #{packet_counter}: IP Source: {ip_src} --> IP Destination: {ip_dst}")
        print(f"Packet #{packet_counter}: Packet Size: {packet_size} bytes")

        # Real-time anomaly detection based on packet sizes where MTU is 1500 
        if packet_size > 1500:
            print("\033[91mPacket #{packet_counter}: Anomaly detected - Packet size above 1500 bytes\033[0m")  # \033[91m for red color

        # Check for unusual TCP ports
        if packet.haslayer(TCP) and packet[TCP].dport not in [80, 443, 22]:
            print(f"Packet #{packet_counter}: Potential malicious activity - Unusual TCP port")

        # Check for unusually high packet rate
        threshold = 500  # Adjust the threshold as needed
        if len(packet) > threshold:
            print(f"Packet #{packet_counter}: Potential malicious activity - High packet rate")

        # Check payload for known malicious signatures
        if packet.haslayer(Raw) and "malicious_string" in str(packet[Raw].load): # replace malicious_string
            print(f"Packet #{packet_counter}: Potential malicious activity - Detected malicious payload")

        # Check for suspicious DNS requests
        if packet.haslayer(DNS) and "malicious_domain.com" in str(packet[DNS].qd): # replace malicious_domain.com
            print(f"Packet #{packet_counter}: Potential malicious activity - Detected suspicious DNS request")


# Sniff packets and process them
sniff(iface="Wi-Fi", prn=process_packet, store=False, timeout=15) # adjust timeout for how long we want it to run for

# Visualization - very minimal for now
plt.plot(packet_sizes)
plt.xlabel("Packet Number")
plt.ylabel("Packet Size (bytes)")
plt.title("Packet Sizes over Time")
plt.show()
