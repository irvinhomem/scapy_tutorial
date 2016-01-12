from scapy.all import *

import matplotlib.pyplot as plt
from numpy.matlib import rand

a = rand(100)
b = rand(100)

myPkt=sr1(IP(dst="www.slashdot.org")/ICMP()/"XXXXXXXXXXX")

#plt.show(ans.plot(lambda x: x[1].id))

#plt.show(ans.scatter(lambda x: x[1].id))
myPkt.show()
type(myPkt)
print("**Packet id = ", myPkt.id)
print("**Packet length = ", myPkt.len)

#plt.scatter(a,b)
plt.scatter(myPkt.id,myPkt.len)

plt.show()