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
pktcap = rdpcap("TestPcaps/BingSearchHTTP.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP.pcap")

############################
# Extract only sequence (dictionary) DNS packets (both requests and responses)
dnsfullframes = [pkt for pkt in pktcap if DNS in pkt]

# Check if successful
print("DNS Entire Frames: ", len(dnsfullframes))
print("Type: ", type(dnsfullframes))
print("Example 1st Frame byte stream:\n", bytes(dnsfullframes[0]))
dnsfullframes[0].show()

#############################
# Extract only DNS protocol section of packets as a sequence (dictionary)
dnsprotopkts = [pkt[IP][UDP][DNS] for pkt in pktcap if DNS in pkt]

# Check if successful
print("DNS Protocol Packets: ", len(dnsprotopkts))
print("Type: ", type(dnsprotopkts))
print("Example 1st Pkt byte stream:\n", bytes(dnsprotopkts[0]))
dnsprotopkts[0].show()

print("2nd pkt byte: ",bytes(dnsprotopkts[1]))

##############################

# Extract only DNS protocol section of packets as a sequence (dictionary) of bytes
dnsprotopktbytes = [bytes(pkt[IP][UDP][DNS]) for pkt in pktcap if DNS in pkt]

print("DNS Protocol Pkt Bytes : ", len(dnsprotopktbytes))
print("Type: ", type(dnsprotopktbytes))
print("Example 1st Pkt byte (in decimal): ", dnsprotopktbytes[0][0])
print("Example 1st Pkt byte (in hex): ", hex(dnsprotopktbytes[0][0]))
print("Example 1st Pkt byte (in hex chr): ", chr(dnsprotopktbytes[0][0]))
print("Type: ",type(dnsprotopktbytes[0][0]))
print("Example 2nd Pkt byte (in decimal): ", dnsprotopktbytes[0][1])
print("Example 2nd Pkt byte (in hex): ", hex(dnsprotopktbytes[0][1]))
print("Example 2nd Pkt byte (in hex chr): ", chr(dnsprotopktbytes[0][1]))
#print("Example 1st Pkt byte :\n", len(bytes(dnsprotopktbytes[0][0])))

################################

# #Define variables to collect sequence of packet lengths
# pktLenSeq = []
#
# #Extract pkt lengths from individual packets
# for pkt in pktcap:
#     #print("Packet Len: ", pkt.len)
#     pktLenSeq.append(pkt.len)
#     #pktLenSeq.append(pkt.payload.len)
#
# lenFreq = Counter(pktLenSeq)
#
# print("LenFreq : ", type(lenFreq))
#
# print(lenFreq)
#lenProbs = []

