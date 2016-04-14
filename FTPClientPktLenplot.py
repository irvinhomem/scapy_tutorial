from scapy.all import *
#from collections import Counter

import matplotlib.pyplot as plt
#import math

# Read from pcap file
#pktcap = rdpcap("TestPcaps/BingSearchHTTP.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP.pcap")
#pktcap = rdpcap("TestPcaps/Google_BBC_HTTP_over_DNS.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP_Normal_Surf.pcapng")
#pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")
pktcap = rdpcap("NewPcaps/FTP/FTP.pcap")                           #<<<-----
#pktcap = rdpcap("TestPcaps/FTP_Normal_PDF_IMG_TXT.pcapng")         #<<-----

# Extract only HTTP protocol section of packets (TCP Payload) and store a list/sequence (dictionary) of lengths
#httpprotopktbytes = [bytes(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]
#httpprotopktlens = [len(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]

# Get the length of the IP packets that are also TCP packets and are not carrying a Raw Payload
# Essentially all TCP (FTP) communication including commands and ACKs from client to server
#ftpprotopktlens = [len(pkt[IP]) for pkt in pktcap if TCP in pkt and not(Raw) in pkt]
ftpprotopktlens = [len(pkt[IP]) for pkt in pktcap if TCP in pkt and pkt[IP].src=='193.10.9.28']     #<<<----------
#ftpprotopktlens = [len(pkt[IP]) for pkt in pktcap if TCP in pkt and pkt[IP].src=='10.0.2.15']      #<<-------
#ftpprotopktlens = [len(pkt[IP]) for pkt in pktcap if TCP in pkt and pkt[TCP].dport==21]
#ftpprotopktlens = [len(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and pkt[TCP].dport==21]

# Plot of Entropy Values
plt.plot(ftpprotopktlens, color="red", marker="+", linestyle="None")
#plt.scatter(httpprotopktlens)  # missing 'y' value ... but actually it's the x value that we need
plt.show()