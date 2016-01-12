from scapy.all import *

import matplotlib.pyplot as plt
from numpy.matlib import rand

#a = rand(100)
#b = rand(100)

# ICMP packets
#myPkt=sr1(IP(dst="www.slashdot.org")/ICMP()/"XXXXXXXXXXX")

# HTTP ??
#ans,unans=sr(IP(dst="www.slashdot.org")/TCP(sport=[RandShort()]*10), timeout=1)
#ans,unans=sr(IP(dst="dsv.su.se")/TCP()/"GET /index.html HTTP/1.0 \n\n")     ## Not working

# DNS
#ans,unans=sr(IP(dst="8.8.8.8")/UDP()/DNS(rd=1,qd=DNSQR(qname="www.slashdot.org")))
#ans,unans=sr(IP(dst="8.8.8.8")/UDP()/DNS(rd=1,qd=DNSQR(qname="www.facebook.com")))
ans,unans=sr(IP(dst="8.8.8.8")/UDP()/DNS(rd=1,qd=DNSQR(qname="www.google.com")))

#plt.show(ans.plot(lambda x: x[1].id))
#plt.show(ans.scatter(lambda x: x[1].id))

#myPkt.show()

#ans.summary()
ans.nsummary()

print("Ans datatype: ", type(ans))

pktidSeq = []
pktlenSeq = []

print("pktidSeq datatype: ", type(pktidSeq))
print("pktlenSeq datatype: ", type(pktlenSeq))

#Create Sequence of id's and sequence of lengths
#ans object contains a tuple of 2 lists the sent packets (snd) and the received packet in response (rcv)
for snd,rcv in ans:
    pktidSeq.append(rcv.id)
    pktlenSeq.append(rcv.len)
    print("PktID:", rcv.id, "PktLen: ", rcv.len)

#Code from single pkt plot
#print("**Packet id = ", myPkt.id)
#print("**Packet length = ", myPkt.len)

#plt.scatter(a,b)
#plt.scatter(myPkt.id,myPkt.len)

plt.scatter(pktidSeq,pktlenSeq)

plt.show()