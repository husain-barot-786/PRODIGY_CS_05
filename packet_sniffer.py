# Network Packet Analyser

from scapy.all import sniff, IP, TCP, UDP, ICMP

def analyze_packet(packet):
    print("\n--- Packet Captured ---")
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")

        if packet.haslayer(TCP):
            print("Protocol Type  : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print("Protocol Type  : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print("Protocol Type  : ICMP")

        print(f"Payload        : {bytes(packet.payload)}")
    else:
        print("Non-IP Packet Captured")

def main():
    print("Starting packet sniffer... (Press Ctrl+C to stop)")
    try:
        sniff(prn=analyze_packet, store=0)
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")

if __name__ == "__main__":
    main()
