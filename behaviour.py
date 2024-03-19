from scapy.all import *
from tkinter import *
from scapy.layers.inet import IP
from sklearn.cluster import KMeans
import numpy as np
from scipy import stats

features = []

# Create a function to set the time length and interface
def set_values():
    global time_length, interface
    time_length = int(time_length_entry.get())
    interface = interface_entry.get()
    root.destroy()

# Create a Tkinter window
root = Tk()
root.title("Network Traffic Analyzer")
root.geometry("1100x800")

# Create a frame to hold the widgets and center the frame
frame = Frame(root)
frame.pack(pady=150)

# Add labels and entry widgets for time length and interface
Label(root, text="Time Length (in seconds):", font=("Verdana", 12)).pack(anchor="center")
time_length_entry = Entry(root, font=("Verdana", 12), width=10)
time_length_entry.insert(0, "5")  # Default value
time_length_entry.pack()

Label(root, text="Interface (must be exact match):", font=("Verdana", 12)).pack(anchor="center")
interface_entry = Entry(root, font=("Verdana", 12), width=20)
interface_entry.insert(0, "Ethernet")  # Default value
interface_entry.pack()

# Add a button to set the values
Button(root, text="Set Values", command=set_values, font=("Verdana", 12)).pack(anchor="center")


# Start the Tkinter event loop
root.mainloop()


def process_packet(packet):

    if IP in packet:         
        packet_size = len(packet)
        # Store features for clustering
        features.append([packet_size])


# Sniff packets and process them in real-time
sniff(iface=interface, prn=process_packet, store=False, timeout=time_length)  # Timeout of 60 seconds

# Convert features to numpy array for clustering
X = np.array(features)

# Calculate the absolute Z-scores for each feature (packet size)
z_scores = np.abs(stats.zscore(X, axis=0))

# Adjust the threshold as needed
threshold = 5
filtered_indices = np.all(z_scores < threshold, axis=1)
X_filtered = X[filtered_indices]

# Initializes a KMeans clustering object with the specified number of clusters
kmeans = KMeans(n_clusters=5, random_state=0).fit(X_filtered)

def get_cluster_info():
    # Return the cluster centers and Z-scores
    return kmeans.cluster_centers_, z_scores

# Print clustering results
print("Cluster Centers:")
print(kmeans.cluster_centers_)
print("Cluster Labels:")
print(kmeans.labels_)