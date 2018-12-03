from scapy.all import *
from scapy.layers.l2 import arping
ans=arping('192.168.5.0/24')
print(ans)