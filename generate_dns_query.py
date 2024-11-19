from scapy.all import *

IPpkt = IP(src="192.168.0.6", dst="192.168.0.5")
UDPpkt = UDP(sport=12345, dport=53, chksum=0)

Qdsec = DNSQR(qname="twysw.example.lan")
DNSpkt = DNS(id=0xAAAA, qr=0, qdcount=1, qd=Qdsec)
Querypkt = IPpkt/UDPpkt/DNSpkt

with open("ip_req.bin", "wb") as f:
    f.write(bytes(Querypkt))
    Querypkt.show()
