from scapy.all import *
#from collections import Counter

import matplotlib.pyplot as plt
#import math

# Read from pcap file
#pktcap = rdpcap("TestPcaps/BingSearchHTTP.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP.pcap")                               #<<<-----
pktcap = rdpcap("TestPcaps/HTTP_Normal_surf_4sites.pcapng")         #<<-----
#pktcap = rdpcap("TestPcaps/Google_BBC_HTTP_over_DNS.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP_Normal_Surf.pcapng")
#pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")

# Extract only HTTP protocol section of packets (TCP Payload) and store a list/sequence (dictionary) of lengths
#httpprotopktbytes = [bytes(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]
#httpprotopktlens = [len(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and pkt[TCP].dport==80]   #<<<-------

#Get the Length of the entire of the entire packet for all HTTP request packets (i.e. dport==80)
#httpprotopktlens = [len(pkt[IP]) for pkt in pktcap if TCP in pkt and Raw in pkt and pkt[TCP].dport==80]

#Get the Length of the entire of the entire packet for all TCP packets with source IP 193.10.9.28
#httpprotopktlens = [len(pkt[IP]) for pkt in pktcap if TCP in pkt and pkt[IP].src=='193.10.9.28']       #<<<-------
httpprotopktlens = [len(pkt[IP]) for pkt in pktcap if TCP in pkt and pkt[IP].src=='10.0.2.15']          #<<-----


# Plot of Entropy Values
plt.plot(httpprotopktlens, color="red", marker="+", linestyle="None")
#plt.scatter(httpprotopktlens)  # missing 'y' value ... but actually it's the x value that we need
plt.show()