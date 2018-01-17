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
#pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")
#pktcap = rdpcap("NewPcaps/HTTP/BBC_normalHTTP.pcapng")
#pktcap = rdpcap("NewPcaps/HTTP/BBC_normalHTTP-2.pcapng")
#pktcap = rdpcap("NewPcaps/HTTP/BBC_normalHTTP-3-ClearedCache.pcapng")
#pktcap = rdpcap("NewPcaps/HTTP/BBC_normalHTTP_incognito.pcapng")
#pktcap = rdpcap("NewPcaps/HTTP/BBC_normalHTTP_incognito-2.pcapng")
#pktcap = rdpcap("NewPcaps/HTTP/BBC_normalHTTP_incognito-3-20160217.pcapng")
#pktcap = rdpcap("NewPcaps/HTTP/BBC_singleHTTPReq_wget-4-20160217.pcapng")
#pktcap = rdpcap("NewPcaps/HTTP/BBC_normalHTTP_wget-6-20160217.pcapng")
#pktcap = rdpcap("NewPcaps/HTTP/BBC_normalHTTP_wget-7-20160218.pcapng")
#pktcap = rdpcap("NewPcaps/HTTP/test.pcapng")

#pktcap = rdpcap("NewPcaps/bbc.co.uk/bbc.co.uk-2016-02-21-T221126.pcapng")
#pktcap = rdpcap("NewPcaps/bbc.co.uk/bbc.co.uk-2016-02-21-T221311.pcapng")

#pktcap = rdpcap("NewPcaps/FTP/ftp-PDF-small.pcapng")
#pktcap = rdpcap("NewPcaps/FTP/ftp-PDF-BIG.pcapng")
#pktcap = rdpcap("NewPcaps/FTP/FTP.pcap")
pktcap = rdpcap("TestPcaps/FTP_Normal_PDF_IMG_TXT.pcapng")



print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("--1--")
# Extract only HTTP protocol section of packets as a sequence (dictionary) of *bytes*
# With destport == 80 ---> HTTP Requests
#httpReqpktbytes = [bytes(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and pkt[TCP].dport==80]
#httpReqpktbytesFreq = [Counter(bytes(pkt[IP][TCP][Raw].load)) for pkt in pktcap if TCP in pkt and Raw in pkt and pkt[TCP].dport==80]
ftpReqpktbytes = [bytes(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and pkt[TCP].dport == 21]
ftpReqpktbytesFreq = [Counter(bytes(pkt[IP][TCP][Raw].load)) for pkt in pktcap if TCP in pkt and Raw in pkt and pkt[TCP].dport == 21]

print("CHECKS for appropriate output ...")
print("Type: ", type(ftpReqpktbytesFreq))
#print("Counter output: ", httpReqpktbytesFreq)
print("Counter output 1st set: ", ftpReqpktbytesFreq[0])
print("Counter output 2nd set: ", ftpReqpktbytesFreq[1])

print("HTTP Protocol Pkt Bytes List length: ", len(ftpReqpktbytes))
print("Type: ", type(ftpReqpktbytes))
print("Example 1st Pkt 1st byte (in decimal): ", ftpReqpktbytes[0][0])
print("Example 1st Pkt 1st byte (in hex): ", hex(ftpReqpktbytes[0][0]))
print("Example 1st Pkt 1st byte (in hex chr): ", chr(ftpReqpktbytes[0][0]))
print("Type: ", type(ftpReqpktbytes[0][0]))
print("Example 1st Pkt 2nd byte (in decimal): ", ftpReqpktbytes[0][1])
print("Example 1st Pkt 2nd byte (in hex): ", hex(ftpReqpktbytes[0][1]))
print("Example 1st Pkt 2nd byte (in hex chr): ", chr(ftpReqpktbytes[0][1]))
print("Type: ", type(ftpReqpktbytes[0][1]))
print("Example 1st Pkt 3rd byte (in decimal): ", ftpReqpktbytes[0][2])
print("Example 1st Pkt 3rd byte (in hex): ", hex(ftpReqpktbytes[0][2]))
print("Example 1st Pkt 3rd byte (in hex chr): ", chr(ftpReqpktbytes[0][2]))
print("Type: ", type(ftpReqpktbytes[0][2]))
#print("Example 1st Pkt byte :\n", len(bytes(dnsprotopktbytes[0][0])))
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

################################
print("--2--")
print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
#Calculate byte/character entropy per packet if it is a FTP packet (destport==21) with Raw Content i.e. FTP commands
perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP][TCP][Raw].load))) for pkt in pktcap if TCP in pkt and Raw in pkt and pkt[TCP].dport==21]
#perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP]))) for pkt in pktcap if TCP in pkt and pkt[IP].src=='193.10.9.28']
#perPktCharEntropySeq = [CalcEntropy(Counter(bytes(pkt[IP]))) for pkt in pktcap if TCP in pkt and pkt[IP].src=='10.0.2.15']
print("Expect Seq Type: ", type(perPktCharEntropySeq))
print("Length: ", len(perPktCharEntropySeq))

# Set Fonts to Arial bold
#print("Font Family: ", matplotlib.rcParams['font.family'])
#print("Font: ", matplotlib.rcParams['font.sans-serif'])
matplotlib.rcParams['font.sans-serif'] = 'Arial'
matplotlib.rcParams['font.weight'] = 'bold'
matplotlib.rcParams['axes.labelweight'] = 'bold'
#print("Font: ", matplotlib.rcParams['font.sans-serif'])
#matplotlib.rc('font', serif='Arial')

# Plot of Entropy Values
#plt.plot(perPktCharEntropySeq, marker="+", markeredgecolor="red", linestyle="solid", color="blue")
plt.plot(perPktCharEntropySeq, marker="+", markeredgecolor="red", linestyle="None", color="blue")
#plt.scatter(perPktCharEntropySeq)  # missing 'y' value ... but actually it's the x value that we need
#plt.suptitle("FTP Request IP-Src Entropy", size = 18)
plt.suptitle("FTP Request App-Layer Entropy", size = 18)
plt.xlabel("Packet Series # (Time)", size=12)
plt.ylabel("Byte (Char) Entropy per packet", size=12)
#plt.show()
plt.savefig(fname='FTP Request App-Layer Entropy.eps', format="eps", dpi=600)