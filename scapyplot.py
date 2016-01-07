from scapy.all import *

import matplotlib
import matplotlib.pyplot as plt


matplotlib.get_backend()
#plt.ion()

ans,unans=sr(IP(dst="www.bbc.co.uk")/TCP(sport=[RandShort()]*200), timeout=1)

plt.show(ans.plot(lambda x: x[1].dport))
#plt.show(ans.scatter(lambda x: x[1].dport))

