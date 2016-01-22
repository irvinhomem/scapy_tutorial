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
#pktcap = rdpcap("TestPcaps/HTTP_Normal_Surf.pcapng")
pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")

############################
# Extract only sequence (dictionary) of frames containing DNS packets (both requests and responses)
dnsfullframes = [pkt for pkt in pktcap if DNS in pkt]

# Check if successful
print("DNS Number of Entire Frames: ", len(dnsfullframes))
print("Type: ", type(dnsfullframes))
print("Example 1st Frame byte stream:\n", bytes(dnsfullframes[0]))
print("Example 2nd Frame byte stream:\n", bytes(dnsfullframes[1]))
# Show the scapy parsed output of the first DNS full frame
#dnsfullframes[0].show()
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

#############################
# Extract only DNS protocol section of packets as a sequence (dictionary)
dnsprotopkts = [pkt[IP][UDP][DNS] for pkt in pktcap if DNS in pkt]

# Check if successful
print("DNS Protocol Packets: ", len(dnsprotopkts))
print("Type: ", type(dnsprotopkts))
#print("Example DNS full Pkt byte stream:\n", bytes(dnsprotopkts.))
print("Example 1st Pkt byte stream:\n", bytes(dnsprotopkts[0]))
# Show the scapy parsed output of the first DNS packet
#dnsprotopkts[0].show()

print("Example 2nd pkt byte string: ", bytes(dnsprotopkts[1]))
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
##############################

# Extract only DNS protocol section of packets as a sequence (dictionary) of bytes
dnsprotopktbytes = [bytes(pkt[IP][UDP][DNS]) for pkt in pktcap if DNS in pkt]
dnsprotopktbytesFreq = [Counter(bytes(pkt[IP][UDP][DNS])) for pkt in pktcap if DNS in pkt]
print("Type: ",type(dnsprotopktbytesFreq))
print("Counter output: ", dnsprotopktbytesFreq)

print("DNS Protocol Pkt Bytes List length: ", len(dnsprotopktbytes))
print("Type: ", type(dnsprotopktbytes))
print("Example 1st Pkt 1st byte (in decimal): ", dnsprotopktbytes[0][0])
print("Example 1st Pkt 1st byte (in hex): ", hex(dnsprotopktbytes[0][0]))
print("Example 1st Pkt 1st byte (in hex chr): ", chr(dnsprotopktbytes[0][0]))
print("Type: ",type(dnsprotopktbytes[0][0]))
print("Example 1st Pkt 2nd byte (in decimal): ", dnsprotopktbytes[0][1])
print("Example 1st Pkt 2nd byte (in hex): ", hex(dnsprotopktbytes[0][1]))
print("Example 1st Pkt 2nd byte (in hex chr): ", chr(dnsprotopktbytes[0][1]))
#print("Example 1st Pkt byte :\n", len(bytes(dnsprotopktbytes[0][0])))

################################

#Calculate byte/character entropy per packet if it is a DNS packet

perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP][UDP][DNS]))) for pkt in pktcap if DNS in pkt]
print("Type: ", type(perPktCharEntropySeq))
print("Length: ", len(perPktCharEntropySeq))

# Plot of Entropy Values
plt.plot(perPktCharEntropySeq, color="red", marker="+", linestyle="None")
#plt.scatter(perPktCharEntropySeq)  # missing 'y' value ... but actually it's the x value that we need
plt.show()

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

