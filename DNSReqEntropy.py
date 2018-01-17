from scapy.all import *
from collections import Counter

import matplotlib.pyplot as plt
import matplotlib
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

#pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")      #<<<--- HTTP over DNS
pktcap = rdpcap("TestPcaps/FTPoverDNS.pcap")        #<<<---- FTP over DNS

# ############################
# # Extract only sequence (dictionary) of frames containing DNS packets (both requests and responses)
# dnsfullframes = [pkt for pkt in pktcap if DNS in pkt]
#
# # Check if successful
# print("DNS Number of Entire Frames: ", len(dnsfullframes))
# print("Type: ", type(dnsfullframes))
# print("Example 1st Frame byte stream:\n", bytes(dnsfullframes[0]))
# print("Example 2nd Frame byte stream:\n", bytes(dnsfullframes[1]))
# # Show the scapy parsed output of the first DNS full frame
# #dnsfullframes[0].show()
# print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

# #############################
# # Extract only DNS protocol section of packets as a sequence (dictionary)
# dnsprotopkts = [pkt[IP][UDP][DNS] for pkt in pktcap if DNS in pkt and pkt[UDP].dport==53]
#
# # Check if successful
# print("DNS Protocol Packets: ", len(dnsprotopkts))
# print("Type: ", type(dnsprotopkts))
# #print("Example DNS full Pkt byte stream:\n", bytes(dnsprotopkts.))
# print("Example 1st Pkt byte stream:\n", bytes(dnsprotopkts[0]))
# # Show the scapy parsed output of the first DNS packet
# #dnsprotopkts[0].show()
#
# print("Example 2nd pkt byte string: ", bytes(dnsprotopkts[1]))
# print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
##############################

# # Extract only DNS protocol section of DNS Request packets (destport=53) as a sequence (dictionary) of bytes
# dnsprotopktbytes = [bytes(pkt[IP][UDP][DNS]) for pkt in pktcap if DNS in pkt and pkt[UDP].dport==53]
# dnsprotopktbytesFreq = [Counter(bytes(pkt[IP][UDP][DNS])) for pkt in pktcap if DNS in pkt and pkt[UDP].dport==53]
# print("Type: ",type(dnsprotopktbytesFreq))
# print("Counter output: ", dnsprotopktbytesFreq)
#
# print("DNS Protocol Pkt Bytes List length: ", len(dnsprotopktbytes))
# print("Type: ", type(dnsprotopktbytes))
# print("Example 1st Pkt 1st byte (in decimal): ", dnsprotopktbytes[0][0])
# print("Example 1st Pkt 1st byte (in hex): ", hex(dnsprotopktbytes[0][0]))
# print("Example 1st Pkt 1st byte (in hex chr): ", chr(dnsprotopktbytes[0][0]))
# print("Type: ",type(dnsprotopktbytes[0][0]))
# print("Example 1st Pkt 2nd byte (in decimal): ", dnsprotopktbytes[0][1])
# print("Example 1st Pkt 2nd byte (in hex): ", hex(dnsprotopktbytes[0][1]))
# print("Example 1st Pkt 2nd byte (in hex chr): ", chr(dnsprotopktbytes[0][1]))
# #print("Example 1st Pkt byte :\n", len(bytes(dnsprotopktbytes[0][0])))
#
# ################################

#Calculate byte/character entropy per packet if it is a DNS request packet (destport=53)

#perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP][UDP][DNS]))) for pkt in pktcap if DNS in pkt and pkt[UDP].dport==53]
perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP][UDP][DNS][DNSQR].qname))) for pkt in pktcap if DNS in pkt and pkt[UDP].dport==53]

print("Type: ", type(perPktCharEntropySeq))
print("Length: ", len(perPktCharEntropySeq))

# Plot of Entropy Values
fig, ax = plt.subplots()

# Set Fonts to Arial bold
#print("Font Family: ", matplotlib.rcParams['font.family'])
#print("Font: ", matplotlib.rcParams['font.sans-serif'])
matplotlib.rcParams['font.sans-serif'] = 'Arial'
matplotlib.rcParams['font.weight'] = 'bold'
matplotlib.rcParams['axes.labelweight'] = 'bold'
#print("Font: ", matplotlib.rcParams['font.sans-serif'])
#matplotlib.rc('font', serif='Arial'


#plt.plot(perPktCharEntropySeq, color="red", marker="+", linestyle="None")
#plt.scatter(perPktCharEntropySeq)  # missing 'y' value ... but actually it's the x value that we need
ax.plot(perPktCharEntropySeq, color="red", marker="+", linestyle="None")
#ax.set_title("HTTP-over-DNS Req (Query_name) Entropy", size=18, fontweight='bold')             #<<<----- HTTP Over DNS
ax.set_title("FTP-over-DNS Req (Query_name) Entropy", size=18, fontweight='bold')               #<<<----- FTP Over DNS
#ax.xaxis.set_tick_params(fontweight='bold')
ax.set_xlabel("Packet Series # (Time)", size=12, fontweight='bold')
ax.set_ylabel("Byte (Char) Entropy per packet", size=12, fontweight='bold')
plt.xticks(fontweight='bold')
plt.yticks(fontweight='bold')
plt.show()
#plt.savefig(fname='FTP-over-DNS Req Query_name Entropy.eps', format="eps", dpi=600)

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

