from scapy.all import *

import matplotlib
import matplotlib.pyplot as plt


matplotlib.get_backend()
#plt.ion()

ans,unans=sr(IP(dst="www.bbc.co.uk")/TCP(sport=[RandShort()]*1000), timeout=1)

plt.show(ans.plot(lambda x: x[1].id))

