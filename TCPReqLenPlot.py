from scapy.all import *
#from collections import Counter

import matplotlib.pyplot as plt
#import math

####################################################################
## This is what was plotted originally, and perhaps in error... ####
####################################################################

# Read from pcap file
#pktcap = rdpcap("TestPcaps/BingSearchHTTP.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP.pcap")
#pktcap = rdpcap("TestPcaps/Google_BBC_HTTP_over_DNS.pcapng")
pktcap = rdpcap("TestPcaps/HTTP_Normal_Surf.pcapng")
#pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")

# Extract only HTTP protocol section of packets (TCP Payload) and store a list/sequence (dictionary) of lengths
#httpprotopktbytes = [bytes(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]
TCPReqpktlens = [len(pkt[IP][TCP]) for pkt in pktcap if TCP in pkt and pkt[TCP].dport==80]
print("Seq Type: ", type(TCPReqpktlens))
print("Seq Length: ", len(TCPReqpktlens))

# Plot of Entropy Values
plt.plot(TCPReqpktlens, color="red", marker="+", linestyle="None")
#plt.scatter(httpprotopktlens)  # missing 'y' value ... but actually it's the x value that we need
plt.show()