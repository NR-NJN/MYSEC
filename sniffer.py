import os
import time
import threading
from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP, wrpcap, conf
from collections import defaultdict

conf.use_npcap = True

load_dotenv()
 
ALLOWLIST_IPS = os.getenv("ALLOWLIST_IPS", "").split(',')

packet_lock = threading.Lock()
captured_packets = []
stop_event = threading.Event() 
scan_tracker = defaultdict(list)
alerted_hosts = set()

 
TIME_WINDOW_SECONDS = 20   
RATE_THRESHOLD = 10        

def packet_callback(packet):
    
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        dport = packet[TCP].dport
        current_time = time.time()

         
        if ip_src in ALLOWLIST_IPS:
            return   
         
        if not any(port == dport for port, ts in scan_tracker[ip_src]):
            scan_tracker[ip_src].append((dport, current_time))

        scan_tracker[ip_src] = [
            (port, ts) for port, ts in scan_tracker[ip_src]
            if current_time - ts <= TIME_WINDOW_SECONDS
        ]
         
        if len(scan_tracker[ip_src]) > RATE_THRESHOLD and ip_src not in alerted_hosts:
            scanned_ports_list = sorted([p for p, ts in scan_tracker[ip_src]])
            print(f"!!! PORT SCAN ALERT !!!")
            print(f"Source IP: {ip_src} scanned {len(scanned_ports_list)} ports in the last {TIME_WINDOW_SECONDS} seconds.")
            print(f"Ports: {scanned_ports_list}")
            print("-" * 20)
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
            print(f"[Writer Thread] Writing {len(packets_to_write)} packets to {filename}")
            wrpcap(filename, packets_to_write, append=True)

def main():
    INTERFACE_TO_SNIFF = os.getenv("INTERFACE_NAME")
    if not INTERFACE_TO_SNIFF:
        print("[!] ERROR: INTERFACE_NAME not set in .env file.")
        return
    CAPTURE_FILENAME = "capture.pcap"
    WRITE_INTERVAL_SECONDS = 60
    if os.path.exists(CAPTURE_FILENAME):
        os.remove(CAPTURE_FILENAME)
    writer_thread = threading.Thread(target=pcap_writer, args=(CAPTURE_FILENAME, WRITE_INTERVAL_SECONDS))
    writer_thread.start()
    print(f"Starting network sniffer with ADVANCED detection on interface: {INTERFACE_TO_SNIFF}")
    if ALLOWLIST_IPS and ALLOWLIST_IPS[0]:
        print(f"Allowlisted IPs: {ALLOWLIST_IPS}")
    print("Press Ctrl+C to stop.")
    try:
        sniff(iface=INTERFACE_TO_SNIFF, prn=packet_callback, store=0, stop_filter=lambda p: stop_event.is_set())
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Shutdown")
    finally:
        stop_event.set()
        writer_thread.join()
        if captured_packets:
            print(f"[Main Thread] Performing final write of {len(captured_packets)} packets")
            wrpcap(CAPTURE_FILENAME, captured_packets, append=True)
        print("[+] Shutdown complete.")

if __name__ == "__main__":
    main()
