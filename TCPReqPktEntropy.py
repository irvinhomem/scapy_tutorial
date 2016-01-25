from scapy.all import *
from collections import Counter

import matplotlib.pyplot as plt
import math

# Entropy calculation function
# H(x) = sum [p(x)*log(1/p)] for i occurrences of x
def CalcEntropy(myFreqDict):
    h = 0.0
    for aKey in myFreqDict:
        # Calculate probability of each even occurrence
        prob = myFreqDict[aKey]/sum(myFreqDict.values())
        # Entropy formula
        h += prob * math.log((1/prob),2)
    return h

# Read from pcap file
#pktcap = rdpcap("TestPcaps/BingSearchHTTP.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP.pcap")
#pktcap = rdpcap("TestPcaps/Google_BBC_HTTP_over_DNS.pcapng")
pktcap = rdpcap("TestPcaps/HTTP_Normal_Surf.pcapng")
#pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")

# Extract only HTTP protocol section of packets (TCP Payload) and store a list/sequence (dictionary) of lengths
#httpprotopktbytes = [bytes(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]
#TCPReqpktlens = [len(pkt[IP][TCP]) for pkt in pktcap if TCP in pkt and pkt[TCP].dport==80]

################################
print("--1--")
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
# Calculate byte/character entropy per packet if it is a TCP (Request) packet (destport==80)
# This includes also TCP handshakes (SYN and ACK parts)
perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP][TCP]))) for pkt in pktcap if TCP in pkt and pkt[TCP].dport==80]
print("Expect Seq Type: ", type(perPktCharEntropySeq))
print("Length: ", len(perPktCharEntropySeq))

# Plot of Entropy Values
#plt.plot(perPktCharEntropySeq, color="red", marker="+", linestyle="None")
plt.plot(perPktCharEntropySeq, color="blue")
#plt.scatter(perPktCharEntropySeq)  # missing 'y' value ... but actually it's the x value that we need
plt.show()