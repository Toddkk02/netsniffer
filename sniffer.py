import ipaddress
import os
import socket
import struct
import sys
import threading
import time

SUBNET = "192.168.4.0/24"
MESSAGE = b"To===D"

class IP:
    def __init__(self, buff=None):
        header = struct.unpack('!BBHHHBBH4s4s', buff)
        self.version = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.length = header[2]
        self.id = header[3]
        self.flags = header[4] >> 13
        self.offset = header[4] & 0x1FFF
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src_ip = socket.inet_ntoa(header[8])
        self.dst_ip = socket.inet_ntoa(header[9])

        # Map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except KeyError:
            self.protocol = str(self.protocol_num)

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.checksum = header[2]
        self.id = header[3]
        self.sequence = header[4]

def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(MESSAGE, (str(ip), 65212))  # Send the message to the specified IP address and port

class Scanner:
    def __init__(self, host):
        self.host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff(self): 
        hosts_up = set([f'{str(self.host)} *'])
        try:
            while True:
                raw_buffer = self.socket.recvfrom(65535)[0]
                ip_header = IP(raw_buffer[:20])
                if ip_header.protocol == "ICMP":
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    icmp_header = ICMP(buf)
                    if icmp_header.type == 3 and icmp_header.code == 3:
                        if ipaddress.ip_address(ip_header.src_ip) in ipaddress.ip_network(SUBNET):
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == MESSAGE:
                                tgt = str(ip_header.src_ip)
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_ip))
                                    print(f"Host {tgt} is up")
        except KeyboardInterrupt:
            print("Sniffing stopped")
            if os.name == "nt":
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            if hosts_up:
                print(f"Up hosts: {', '.join(hosts_up)}")
                print(f"on: {SUBNET}")
                for host in sorted(hosts_up):
                    print(f"{host} -> {SUBNET}")
            sys.exit()

def sniff(host):
    # If we're on Windows, we need to send an IOCTL to set up promiscuous mode
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # Read a packet
            raw_buffer = sniffer.recvfrom(65535)[0]
            
            # Create an IP header from the first 20 bytes
            ip_header = IP(raw_buffer[:20])
            
            # Print out the protocol that was detected and the hosts
            print(f"Protocol: {ip_header.protocol} {ip_header.src_ip} -> {ip_header.dst_ip}")

            # If it's ICMP, we want it
            if ip_header.protocol == "ICMP":
                print(f"Version: {ip_header.version}")
                print(f"Header Length: {ip_header.ihl} TTL: {ip_header.ttl}")
                
                # Calculate where our ICMP packet starts
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + 8]
                
                # Create our ICMP structure
                icmp_header = ICMP(buf)
                
                print(f"ICMP -> Type: {icmp_header.type} Code: {icmp_header.code}\n")

    except KeyboardInterrupt:
        # If we're on Windows, turn off promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()

if __name__ == "__main__":
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        # Try to get the actual IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            host = s.getsockname()[0]
        except Exception:
            host = '127.0.0.1'
        finally:
            s.close()
    
    # Update SUBNET based on the host IP
    ip = ipaddress.ip_address(host)
    SUBNET = str(ipaddress.ip_network(f'{ip}/24', strict=False))
    
    print(f"Sniffing on {host}")
    print(f"Subnet: {SUBNET}")
    s = Scanner(host)
    time.sleep(5)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()