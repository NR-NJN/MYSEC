from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from dotenv import load_dotenv
import os
load_dotenv()

scanned_ports = defaultdict(set)
PORT_SCAN_THRESHOLD = 3 #change depending upon what you want as the trigger mech
alerted_hosts = set()

def packet_callback(packet):
    
   
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        dport = packet[TCP].dport

        scanned_ports[ip_src].add(dport)

       
        if len(scanned_ports[ip_src]) > PORT_SCAN_THRESHOLD:
            
            if ip_src not in alerted_hosts:
                print(f"!!! PORT SCAN ALERT !!!")
                print(f"Source IP: {ip_src} is scanning multiple ports.")
                print(f"Scanned ports ({len(scanned_ports[ip_src])}): {sorted(list(scanned_ports[ip_src]))}")
                print("-" * 20)
                alerted_hosts.add(ip_src)

def main():
    INTERFACE_TO_SNIFF = os.getenv("INTERFACE_NAME")
    if not INTERFACE_TO_SNIFF:
        print("INTERFACE_NAME not set in .env file. Please create a .env file and add it.")
        return
    print(f"Starting network sniffer on interface: {INTERFACE_TO_SNIFF}")
    sniff(iface=INTERFACE_TO_SNIFF, prn=packet_callback, store=0)


if __name__ == "__main__":
    main()

