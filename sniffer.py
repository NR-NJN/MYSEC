import os
import time
import threading
from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP, wrpcap
from collections import defaultdict


load_dotenv()
packet_lock = threading.Lock()

captured_packets = []

stop_event = threading.Event()


scanned_ports = defaultdict(set)
PORT_SCAN_THRESHOLD = 3
alerted_hosts = set()

def packet_callback(packet):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        dport = packet[TCP].dport
        scanned_ports[ip_src].add(dport)
        if len(scanned_ports[ip_src]) > PORT_SCAN_THRESHOLD and ip_src not in alerted_hosts:
            print(f"!!! PORT SCAN ALERT !!! Source IP: {ip_src}")
            alerted_hosts.add(ip_src)
            
    with packet_lock:
        captured_packets.append(packet)

def pcap_writer(filename, interval):
    print(f"[Writer Thread] Started. Will write to '{filename}' every {interval} seconds.")
    while not stop_event.is_set():
        stop_event.wait(interval)
        
        packets_to_write = []
        with packet_lock:
            if captured_packets:
                packets_to_write = captured_packets[:]
                captured_packets.clear()
        
        if packets_to_write:
            print(f"[Writer Thread] Writing {len(packets_to_write)} packets to {filename}...")
            wrpcap(filename, packets_to_write, append=True)

def main():
    INTERFACE_TO_SNIFF = os.getenv("INTERFACE_NAME")
    if not INTERFACE_TO_SNIFF:
        print("[!] ERROR: INTERFACE_NAME not set in .env file.")
        return

    CAPTURE_FILENAME = "capture.pcap"
    WRITE_INTERVAL_SECONDS = 20 

    
    if os.path.exists(CAPTURE_FILENAME):
        os.remove(CAPTURE_FILENAME)

    writer_thread = threading.Thread(target=pcap_writer, args=(CAPTURE_FILENAME, WRITE_INTERVAL_SECONDS))
    writer_thread.start()

    print(f"Starting continuous network sniffer on interface: {INTERFACE_TO_SNIFF}")
    print("Press Ctrl+C to stop.")

    try:
        
        sniff(iface=INTERFACE_TO_SNIFF, prn=packet_callback, store=0, stop_filter=lambda p: stop_event.is_set())
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Shutting down gracefully...")
    finally:
        
        stop_event.set()
        writer_thread.join() 
        print("[+] Sniffer and writer threads have been stopped.")
        
        if captured_packets:
            print(f"[Main Thread] Performing final write of {len(captured_packets)} packets...")
            wrpcap(CAPTURE_FILENAME, captured_packets, append=True)
        print("[+] Shutdown complete.")


if __name__ == "__main__":
    main()