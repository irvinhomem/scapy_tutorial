from scapy.all import *
from collections import Counter

import matplotlib.pyplot as plt
import math

##########################################################################################################
## Exactly the same as DNSReqPktEntrpyConsecDiff.py, except for the different packet capture used ... ####
##########################################################################################################

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
#pktcap = rdpcap("TestPcaps/HTTP_Normal_Surf.pcapng")
#pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")
pktcap = rdpcap("TestPcaps/HTTPoverSSHoverDNS.pcap")

################################
print("--1--")
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
# Calculate byte/character entropy per packet if it is a DNS (Request) packet (destport==53)
perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP][UDP][DNS]))) for pkt in pktcap if DNS in pkt and pkt[UDP].dport==53]
print("Expect Seq Type: ", type(perPktCharEntropySeq))
print("Length: ", len(perPktCharEntropySeq))

# Get the differences of entropy between consecutive packets
consecpktEntrpyDiff = []
for idx, obj in enumerate(perPktCharEntropySeq):
    if idx < len(perPktCharEntropySeq)-1:
        consecpktEntrpyDiff.append(perPktCharEntropySeq[idx+1] - perPktCharEntropySeq[idx])

print("Expect Seq Type: ", type(consecpktEntrpyDiff))
print("Length: ", len(consecpktEntrpyDiff))

# Plot of Entropy Values differences
plt.plot(consecpktEntrpyDiff, color="red", marker="+", linestyle="None")
#plt.plot(perPktCharEntropySeq, color="red", marker="+", linestyle="None")
#plt.scatter(perPktCharEntropySeq)  # missing 'y' value ... but actually it's the x value that we need
plt.show()