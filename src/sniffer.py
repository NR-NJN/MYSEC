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
port_scan_tracker = defaultdict(list)
port_scan_alerted = set()
PORT_SCAN_TIME_WINDOW = 20
PORT_SCAN_RATE_THRESHOLD = 10
 
ddos_tracker = defaultdict(list)
ddos_alerted = set()
DDOS_TIME_WINDOW = 10   
DDOS_PACKET_THRESHOLD = 500  

def packet_callback(packet):
     
    if IP in packet:  
        ip_src = packet[IP].src
        current_time = time.time()

         
        if ip_src in ALLOWLIST_IPS:
            return

         
        ddos_tracker[ip_src].append(current_time)
        ddos_tracker[ip_src] = [ts for ts in ddos_tracker[ip_src] if current_time - ts <= DDOS_TIME_WINDOW]
        
        if len(ddos_tracker[ip_src]) > DDOS_PACKET_THRESHOLD and ip_src not in ddos_alerted:
            print("\n" + "="*40)
            print(f"!!! DDOS ATTACK DETECTED !!!")
            print(f"Source IP: {ip_src} sent {len(ddos_tracker[ip_src])} packets in the last {DDOS_TIME_WINDOW} seconds.")
            print("="*40 + "\n")
            ddos_alerted.add(ip_src)

         
        if TCP in packet:
            dport = packet[TCP].dport
            if not any(port == dport for port, ts in port_scan_tracker[ip_src]):
                port_scan_tracker[ip_src].append((dport, current_time))

            port_scan_tracker[ip_src] = [
                (port, ts) for port, ts in port_scan_tracker[ip_src]
                if current_time - ts <= PORT_SCAN_TIME_WINDOW
            ]
            
            if len(port_scan_tracker[ip_src]) > PORT_SCAN_RATE_THRESHOLD and ip_src not in port_scan_alerted:
                scanned_ports_list = sorted([p for p, ts in port_scan_tracker[ip_src]])
                print("\n" + "="*40)
                print(f"!!! PORT SCAN ALERT !!!")
                print(f"Source IP: {ip_src} scanned {len(scanned_ports_list)} ports in the last {PORT_SCAN_TIME_WINDOW} seconds.")
                print(f"Ports: {scanned_ports_list}")
                print("="*40 + "\n")
                port_scan_alerted.add(ip_src)

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
