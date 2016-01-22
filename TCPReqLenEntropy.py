from scapy.all import *
from collections import Counter

import matplotlib.pyplot as plt
import math

####################################################################
## This DOES NOT WORK ... and probably doesn't make sense ...   ####
####################################################################

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
pktcap = rdpcap("TestPcaps/HTTP.pcap")
#pktcap = rdpcap("TestPcaps/Google_BBC_HTTP_over_DNS.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP_Normal_Surf.pcapng")
#pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")

# Extract only HTTP protocol section of packets (TCP Payload) and store a list/sequence (dictionary) of lengths
#httpprotopktbytes = [bytes(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]
#TCPReqpktlens = [len(pkt[IP][TCP]) for pkt in pktcap if TCP in pkt and pkt[TCP].dport==80]

# Collect Seq/list of lengths
pktlenSeq = [len(pkt[IP][TCP]) for pkt in pktcap if TCP in pkt and pkt[TCP].dport==80]
print("Type: ", type(pktlenSeq))
print("Length of list/seq: ", len(pktlenSeq))
print("1st item value:", pktlenSeq[0])
print("2nd item value:", pktlenSeq[1])
print("3rd item value:", pktlenSeq[2])
print("4rd item value:", pktlenSeq[3])

pktLenFreqs = Counter(pktlenSeq)
print("Counter Freqs: ", pktLenFreqs)

################################
print("--2--")
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
#Calculate length entropy per packet if it is a TCP packet (destport==80)
perPktLenEntropySeq = CalcEntropy(pktLenFreqs)
print("Expect Seq Type: ", type(perPktLenEntropySeq))
print("Length: ", len(perPktLenEntropySeq))

# Plot of Entropy Values
plt.plot(perPktLenEntropySeq, color="red", marker="+", linestyle="None")
#plt.scatter(perPktCharEntropySeq)  # missing 'y' value ... but actually it's the x value that we need
plt.show()