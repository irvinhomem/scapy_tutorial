from scapy.all import *

import matplotlib.pyplot as plt
from numpy.matlib import rand

#matplotlib.get_backend()
#plt.ion()
a = rand(100)
b = rand(100)

ans,unans=sr(IP(dst="www.bbc.co.uk")/TCP(sport=[RandShort()]*1000), timeout=1)

#plt.show(ans.plot(lambda x: x[1].id))

#plt.show(ans.scatter(lambda x: x[1].id))

plt.scatter(a,b)
plt.show()



