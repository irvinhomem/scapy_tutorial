from scapy.all import *

import matplotlib.pyplot as plt

#Read from pcap file
pktcap = rdpcap("TestPcaps/BingSearchHTTP.pcapng")

#Define variables to collect sequences of pkt ID's and packet lengths
pktIDseq = []
pktLenSeq = []

#Extract pkt id's and lengths from individual packets
for pkt in pktcap:
    pktIDseq.append(pkt.id)
    pktLenSeq.append(pkt.len)

#Plot the sequences as a scatter plot
plt.scatter(pktIDseq, pktLenSeq, color="red", marker="+")
#Markers can be 'o','+','x','*','^' and many others
#Colors can be words or characters: e.g. 'red' or 'r', 'blue' or 'b'

#Show the plot
plt.show()