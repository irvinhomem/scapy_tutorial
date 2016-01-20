from scapy.all import *
from collections import Counter

import matplotlib.pyplot as plt
import math

#Read from pcap file
pktcap = rdpcap("TestPcaps/BingSearchHTTP.pcapng")
#pktcap = rdpcap("TestPcaps/HTTPng.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP.pcap")
#pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")

#Define variables to collect sequence of packet lengths
pktLenSeq = []

#Extract pkt lengths from individual packets
for pkt in pktcap:
    #print("Packet Len: ", pkt.len)
    pktLenSeq.append(pkt.len)
    #pktLenSeq.append(pkt.payload.len)

lenFreq = Counter(pktLenSeq)

print("LenFreq : ", type(lenFreq))

print(lenFreq)
#lenProbs = []

#Calculate entropy
#H(x) = sum [p(x)*log(1/p)] for i occurrences of x
h = 0.0

for x in lenFreq:
    p = lenFreq[x]/sum(lenFreq.values())
    h += p * math.log((1/p),2)

print("H = ",h)


