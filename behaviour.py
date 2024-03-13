from scapy.all import *
from scapy.layers.inet import IP
from sklearn.cluster import KMeans
import numpy as np

features = []

def process_packet(packet):

    if IP in packet:         
        packet_size = len(packet)
        # Store features for clustering
        features.append([packet_size])


# Sniff packets and process them in real-time
sniff(iface="Ethernet", prn=process_packet, store=False, timeout=10)  # Timeout of 60 seconds

# Convert features to numpy array for clustering
X = np.array(features)

# Initializes a KMeans clustering object with the specified number of clusters
kmeans = KMeans(n_clusters=5, random_state=0).fit(X)

def get_cluster_centers():
    
    # Return the cluster centers
    return kmeans.cluster_centers_

# Print clustering results
print("Cluster Centers:")
print(kmeans.cluster_centers_)
print("Cluster Labels:")
print(kmeans.labels_)