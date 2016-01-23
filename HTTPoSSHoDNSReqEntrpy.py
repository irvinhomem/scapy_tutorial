from scapy.all import *
from collections import Counter

import matplotlib.pyplot as plt
import math

##############################################################################################
## Exactly the same as DNSReqEntropy.py, except for the different packet capture used ... ####
##############################################################################################

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

#Calculate byte/character entropy per packet if it is a DNS request packet (destport=53)

perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP][UDP][DNS]))) for pkt in pktcap if DNS in pkt and pkt[UDP].dport==53]
print("Type: ", type(perPktCharEntropySeq))
print("Length: ", len(perPktCharEntropySeq))

# Plot of Entropy Values
plt.plot(perPktCharEntropySeq, color="red", marker="+", linestyle="None")
#plt.scatter(perPktCharEntropySeq)  # missing 'y' value ... but actually it's the x value that we need
plt.show()

