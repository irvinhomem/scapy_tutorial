from scapy.all import *
#from collections import Counter

import matplotlib.pyplot as plt
#import math

####################################################################
## This is what was plotted originally, and perhaps in error... ####
####################################################################

# Read from pcap file
#pktcap = rdpcap("TestPcaps/BingSearchHTTP.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP.pcap")
#pktcap = rdpcap("TestPcaps/Google_BBC_HTTP_over_DNS.pcapng")
#pktcap = rdpcap("TestPcaps/HTTP_Normal_Surf.pcapng")
pktcap = rdpcap("TestPcaps/HTTPoverDNS.pcap")
#pktcap = rdpcap("TestPcaps/FTPoverDNS.pcap")
#pktcap = rdpcap("TestPcaps/HTTPoverSSHoverDNS.pcap")

# Extract only HTTP protocol section of packets (TCP Payload) and store a list/sequence (dictionary) of lengths
#httpprotopktbytes = [bytes(pkt[IP][TCP][Raw].load) for pkt in pktcap if TCP in pkt and Raw in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80)]
#DNSReqpktlens = [len(pkt[IP][UDP][DNS]) for pkt in pktcap if DNS in pkt and pkt[UDP].dport==53]     #<<<------
#DNSReqpktlens = [len(pkt[IP]) for pkt in pktcap if DNS in pkt and pkt[UDP].dport==53]
DNSReqpktlens = [len(pkt[IP][UDP][DNS][DNSQR].qname) for pkt in pktcap if DNS in pkt and pkt[UDP].dport==53]    #<<<----- This is what we plot now

print("Seq Type: ", type(DNSReqpktlens))
print("Seq Length: ", len(DNSReqpktlens))

# Plot of Entropy Values
fig, ax = plt.subplots()
#plt.plot(DNSReqpktlens, color="red", marker="+", linestyle="None")
#plt.scatter(httpprotopktlens)  # missing 'y' value ... but actually it's the x value that we need
ax.plot(DNSReqpktlens, color="red", marker="+", linestyle="None")
ax.set_title("HTTP-over-DNS Req (Query_name) Lengths")
ax.set_xlabel("Packet Series # (Time)")
ax.set_ylabel("Length")

plt.show()