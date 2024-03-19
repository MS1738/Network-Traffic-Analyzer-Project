from scapy.all import *
from scapy.layers.inet import IP, TCP
from tkinter import *
from matplotlib.backends.backend_tkagg import *
from tkinter import messagebox
import matplotlib.pyplot as plt
import time
from behaviour import get_cluster_info # runs the behaviour analysis file first

packet_counter = 0  # Global variable to store the packet counter
packet_sizes = []    # List to store packet sizes for visualization
malicious_domains = [] # malicious domain names

malicious_packets_counter = 0
anamoly_packets_counter = 0

time_length = 5 # duration of program
interface = "Ethernet" # interface to sniff packets on

start_time = time.time()

cluster_centers, z_scores = get_cluster_info() # to store cluster center and z-score information after running behavour analysis file

def process_packet(packet):
    global malicious_packets_counter
    global anamoly_packets_counter
    global packet_counter  # Use the global packet_counter variable
    packet_counter += 1  # Increment the packet counter

    if IP in packet:            # 1. Packet Capture and Analysis - IP header
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_size = len(packet)
        packet_sizes.append(packet_size)  # Add packet size to the list for visualization

        # Print packet number, advanced packet information, and packet size
        print(f"Packet #{packet_counter}: IP Source: {ip_src} --> IP Destination: {ip_dst}")
        print(f"Packet #{packet_counter}: Packet Size: {packet_size} bytes")
  
        # Check if packet size is within a reasonable range of any cluster center
        is_anomaly = True
        threshold = 5 # value we are using to determine if a packet size is within a reasonable range of any cluster center
        for z_score in z_scores:
            # If the absolute Z-score for a packet size is less than or equal to this threshold, we consider the packet size to be within a reasonable range.
            if abs(z_score) <= threshold:  # if the absolute Z-score is less than or equal to the threshold, meaning reasonable range
                is_anomaly = False
                break

        if is_anomaly:
            print(f"\033[91mPacket #{packet_counter}: Anomaly detected - Packet size outside cluster centers range\033[0m")
            anamoly_packets_counter += 1
                        
        # Check for unusual TCP ports
        if packet.haslayer(TCP) and packet[TCP].dport not in [80, 443, 22]:
            print(f"Packet #{packet_counter}: Potential malicious activity - Unusual TCP port (Source: {ip_src}, Destination: {ip_dst}, Port: {packet[TCP].dport})")
            malicious_packets_counter += 1
            
            
        # Detect HTTP packets
        if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].dport == 443):
            print(f"Packet #{packet_counter}: HTTP/HTTPS packet detected")               
            
        # Read the list of malicious domain names or IP addresses from a file
        file_path = "C:/Users/Maulik Suryavanshi/VSCode Projects/Python/Network Traffic Analyzer/Network-Traffic-Analyzer-Project/malicious_domains.txt"
        with open(file_path, "r") as file:
            malicious_domains = [line.strip() for line in file]

        # if the packet has the domain from that list, flag that packet as malicious
        if packet.haslayer(DNS) and packet[DNS].qd is not None and str(packet[DNS].qd.qname, 'utf-8') in malicious_domains:
            print(f"Packet #{packet_counter}: Potential malicious activity - Detected suspicious DNS request") 
            malicious_packets_counter += 1 

        # Check payload for known malicious signatures
        if packet.haslayer(Raw):
            payload = str(packet[Raw].load, 'utf-8', errors='ignore')  # Convert payload to string
            malicious_strings = [
                "' OR 1=1 --",
                "'; DROP TABLE users--",
                "<script>alert('XSS')</script>",
                "; ls -la",
                "& rm -rf /",
                # Add more malicious strings here
            ]
            for malicious_string in malicious_strings:
                if malicious_string in payload:
                    print(f"Packet #{packet_counter}: Potential malicious activity - Detected malicious payload containing: {malicious_string}")
                    malicious_packets_counter += 1
                    break  # Exit the loop after the first match is found


# Sniff packets and process them
sniff(iface=interface, prn=process_packet, store=False, timeout=time_length)

# Calculate elapsed time
end_time = time.time()
elapsed_time = end_time - start_time

# Create a new Tkinter window for the summary
summary_window = Tk()
summary_window.title("Summary")

# Get the screen width and height
screen_width = summary_window.winfo_screenwidth()
screen_height = summary_window.winfo_screenheight()

# Set the geometry to fit the screen
summary_window.geometry(f"{screen_width}x{screen_height}")

# Add a label to display the summary
summary_label = Label(summary_window, text="Summary of Network Traffic Analysis", font=("Verdana", 16, "bold"))
summary_label.pack(pady=10)

# Add a text box to display the summary information
summary_text = Text(summary_window, width=100, height=20, font=("Verdana", 12))
summary_text.pack(pady=10)

# Display the summary information
summary_text.insert(END, f"Total Packets Analyzed: {packet_counter}\n", ('Verdana', 12)) 
summary_text.insert(END, f"Malicious Packets Detected: {malicious_packets_counter}\n", ('Verdana', 12))
summary_text.insert(END, f"Anomalies Detected: {anamoly_packets_counter}\n", ('Verdana', 12))
summary_text.insert(END, f"Time Elapsed: {elapsed_time:.2f} seconds\n", ('Verdana', 12))
# Add more summary information as needed

# # Add a button to further inspect malicious packets
# def inspect_packets():
#     # Add code here to display further inspection options for malicious packets
#     pass

# inspect_button = Button(summary_window, text="Inspect Malicious Packets", command=inspect_packets, font=("Arial", 12))
# inspect_button.pack(pady=10)

# Add the packet size visualization
plt.figure(figsize=(8, 6))
plt.plot(packet_sizes)
plt.xlabel("Packet Number")
plt.ylabel("Packet Size (bytes)")
plt.title("Packet Sizes over Time")
plt.tight_layout()

# Create a canvas to display the plot in the Tkinter window
canvas = FigureCanvasTkAgg(plt.gcf(), master=summary_window)
canvas.draw()
canvas.get_tk_widget().pack()

# Function to handle window closing event
def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        summary_window.destroy()

# Bind the closing event to the window
summary_window.protocol("WM_DELETE_WINDOW", on_closing)

# Start the Tkinter event loop for the summary window
summary_window.mainloop()
