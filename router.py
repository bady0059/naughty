import requests


class Router:
    def __init__(self, mac, channel, ssid, ip=None, devices=[]):
        self.mac = mac
        self.ip = ip
        self.devices = devices
        self.channel = channel
        
        if type(ssid) == str:
            self.ssid = ssid
        else:
            self.ssid = ssid.decode()

    def get_ssid(self):
        return self.ssid

    def get_ip(self):
        return "192.168.14.1"# for now
        if self.ip == None:
            self.ip = ""
        return self.ip

    def get_mac(self):
        return self.mac

    def get_channel(self):
        return self.channel
    
    def get_devices(self):
        return self.devices

    def get_company(self): 
        f = open('macscomp.txt', 'r')
        lines = f.readlines()
        
        mac = self.mac[:8].replace(":", "")
        for line in lines:
            vals = line.split(" ", 1)
            if vals[0] == mac:
                return vals[1][:-1]
        return "unknown"
    
    def get_list(self):
        return [self.ssid, self.mac, str(self.channel), self.get_company()]
    
    def __str__(self):
        return "SSID: " + self.ssid + " MAC: " + self.mac + " Channel: " + str(self.channel) + " Company: " + self.get_company()
