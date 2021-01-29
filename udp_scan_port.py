#!/usr/bin/python
"""
udp_scan_py --- Use scapy too scan udp port
python version:2.7+
https://github.com/Kali-i386/Scapy
"""

import logging
from scapy import *
import sys,subprocess
import time

logging.getlogger("scapy.runtime").setlevel(logging.ERROR)

if len(sys.argv) < 4:
    print("Usage:python udp_scan_port.py [ip][port1][port2]")
    input()

ip = sys.argv[1]
port1 = sys.argv[2]
port2 = sys.argv[3]

for port in range(port1,port2):
    a = srl(IP(dst=ip) / UDP(dport=port),
            timeout=0.1,
            verbose=0)
    time.sleep(1)
    if a == None:
        print("The "+str(port)+" is open")
    else:
        pass
    
