from scapy.all import *
from scapy.layers.inet import IP
from sklearn.cluster import KMeans
import numpy as np
from scipy import stats

features = []

time_length = 5 # duration of program
interface = "Ethernet" # interface to sniff packets on

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