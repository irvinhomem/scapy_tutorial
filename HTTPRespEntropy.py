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

print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("--1--")
# Extract only HTTP protocol section of packets as a sequence (dictionary) of *bytes*
# With destport == 80 ---> HTTP Requests
httpResppktbytes = [bytes(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and pkt[TCP].sport==80]
httpResppktbytesFreq = [Counter(bytes(pkt[IP][TCP][Raw].load)) for pkt in pktcap if TCP in pkt and Raw in pkt and pkt[TCP].sport==80]

print("CHECKS for appropriate output ...")
print("Type: ",type(httpResppktbytesFreq))
#print("Counter output: ", httpResppktbytesFreq)
print("Counter output 1st set: ", httpResppktbytesFreq[0])
print("Counter output 2nd set: ", httpResppktbytesFreq[1])

print("HTTP Protocol Pkt Bytes List length: ", len(httpResppktbytes))
print("Type: ", type(httpResppktbytes))
print("Example 1st Pkt 1st byte (in decimal): ", httpResppktbytes[0][0])
print("Example 1st Pkt 1st byte (in hex): ", hex(httpResppktbytes[0][0]))
print("Example 1st Pkt 1st byte (in hex chr): ", chr(httpResppktbytes[0][0]))
print("Type: ",type(httpResppktbytes[0][0]))
print("Example 1st Pkt 2nd byte (in decimal): ", httpResppktbytes[0][1])
print("Example 1st Pkt 2nd byte (in hex): ", hex(httpResppktbytes[0][1]))
print("Example 1st Pkt 2nd byte (in hex chr): ", chr(httpResppktbytes[0][1]))
print("Type: ",type(httpResppktbytes[0][1]))
print("Example 1st Pkt 3rd byte (in decimal): ", httpResppktbytes[0][2])
print("Example 1st Pkt 3rd byte (in hex): ", hex(httpResppktbytes[0][2]))
print("Example 1st Pkt 3rd byte (in hex chr): ", chr(httpResppktbytes[0][2]))
print("Type: ",type(httpResppktbytes[0][2]))
#print("Example 1st Pkt byte :\n", len(bytes(dnsprotopktbytes[0][0])))
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

################################
print("--2--")
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
#Calculate byte/character entropy per packet if it is a HTTP packet (srcport/destport==80) with Raw Content
perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP][TCP][Raw].load))) for pkt in pktcap if TCP in pkt and Raw in pkt and pkt[TCP].sport==80]
print("Expect Seq Type: ", type(perPktCharEntropySeq))
print("Length: ", len(perPktCharEntropySeq))

# Plot of Entropy Values
plt.plot(perPktCharEntropySeq, color="red", marker="+", linestyle="None")
#plt.scatter(perPktCharEntropySeq)  # missing 'y' value ... but actually it's the x value that we need
plt.show()