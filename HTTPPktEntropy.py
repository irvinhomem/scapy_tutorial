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
pktcap = rdpcap("TestPcaps/HTTP.pcap")
#pktcap = rdpcap("TestPcaps/Google_BBC_HTTP_over_DNS.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP_Normal_Surf.pcapng")
#pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")

############################
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("--1--")
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
# Extract only sequence (dictionary) of frames containing HTTP packets (both requests and responses)
# Includes also any TCP Handshake packets to/from port 80
httpfullframes = [pkt for pkt in pktcap if TCP in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]

# Check if successful
print("HTTP/TCP Number of Entire Frames: ", len(httpfullframes))
print("Type: ", type(httpfullframes))
print("Type of list item 1: ", type(httpfullframes[0]))
print("Example 1st Frame byte stream:\n", bytes(httpfullframes[0]))
print("Example 2nd Frame byte stream:\n", bytes(httpfullframes[1]))
# Show the scapy parsed output of the first HTTP full frame
#httpfullframes[0].show()
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

############################
print("--2--")
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
# Extract only sequence (dictionary) of frames containing HTTP packets (both requests and responses) that have Content
# Includes any TCP Handshake packets to/from port 80 (Including all ACKs)
# The 'Raw' dictionary (directive) item says that there is content in the HTTP/TCP packet
httpfullframes = [pkt for pkt in pktcap if TCP in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]

# Check if successful
print("HTTP Number of Entire Frames with HTTP Content(Raw): ", len(httpfullframes))
print("Type: ", type(httpfullframes))
print("Type of list item 1: ", type(httpfullframes[0]))
print("Example 1st Frame byte stream:\n", bytes(httpfullframes[0]))
print("Example 2nd Frame byte stream:\n", bytes(httpfullframes[1]))
# Show the scapy parsed output of the first HTTP full frame
#httpfullframes[0].show()
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

#############################
print("--3--")
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
# Extract only HTTP protocol section of packets as a sequence (dictionary)
httpprotopkts = [pkt[IP][TCP][Raw].load for pkt in pktcap if TCP in pkt and Raw in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]

# Check if successful
print("HTTP Protocol (Only) Packets (No Ethernet, IP or TCP Headers): ", len(httpprotopkts))
print("Type: ", type(httpprotopkts))
#print("Example DNS full Pkt byte stream:\n", bytes(httpprotopkts.))
print("Example 1st Pkt byte stream:\n", bytes(httpprotopkts[0]))
# Show the scapy parsed output of the first DNS packet
#httpprotopkts[0].show()

print("Example 2nd pkt byte string:\n", bytes(httpprotopkts[1]))
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

##############################
print("--4--")
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
# Extract only HTTP protocol section of packets as a sequence (dictionary) of *bytes*
httpprotopktbytes = [bytes(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]
httpprotopktbytesFreq = [Counter(bytes(pkt[IP][TCP][Raw].load)) for pkt in pktcap if TCP in pkt and Raw in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]
print("Type: ",type(httpprotopktbytesFreq))
#print("Counter output: ", httpprotopktbytesFreq)
print("Counter output 1st set: ", httpprotopktbytesFreq[0])
print("Counter output 2nd set: ", httpprotopktbytesFreq[1])

print("HTTP Protocol Pkt Bytes List length: ", len(httpprotopktbytes))
print("Type: ", type(httpprotopktbytes))
print("Example 1st Pkt 1st byte (in decimal): ", httpprotopktbytes[0][0])
print("Example 1st Pkt 1st byte (in hex): ", hex(httpprotopktbytes[0][0]))
print("Example 1st Pkt 1st byte (in hex chr): ", chr(httpprotopktbytes[0][0]))
print("Type: ",type(httpprotopktbytes[0][0]))
print("Example 1st Pkt 2nd byte (in decimal): ", httpprotopktbytes[0][1])
print("Example 1st Pkt 2nd byte (in hex): ", hex(httpprotopktbytes[0][1]))
print("Example 1st Pkt 2nd byte (in hex chr): ", chr(httpprotopktbytes[0][1]))
print("Type: ",type(httpprotopktbytes[0][1]))
print("Example 1st Pkt 3rd byte (in decimal): ", httpprotopktbytes[0][2])
print("Example 1st Pkt 3rd byte (in hex): ", hex(httpprotopktbytes[0][2]))
print("Example 1st Pkt 3rd byte (in hex chr): ", chr(httpprotopktbytes[0][2]))
print("Type: ",type(httpprotopktbytes[0][2]))
#print("Example 1st Pkt byte :\n", len(bytes(dnsprotopktbytes[0][0])))

################################

print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
#Calculate byte/character entropy per packet if it is a HTTP packet (srcport/destport==80) (includes all ACKs and those with Raw Content)
#perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP][TCP]))) for pkt in pktcap if TCP in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]
perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP][TCP]))) for pkt in pktcap if TCP in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]
print("Expect Seq Type: ", type(perPktCharEntropySeq))
print("Length: ", len(perPktCharEntropySeq))

# Plot of Entropy Values
plt.plot(perPktCharEntropySeq, color="red", marker="+", linestyle="None")
#plt.scatter(perPktCharEntropySeq)  # missing 'y' value ... but actually it's the x value that we need
plt.show()



