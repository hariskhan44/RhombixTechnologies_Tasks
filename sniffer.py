# Import necessary modules from Scapy
from scapy.all import sniff, IP, TCP, UDP

# Function to process each captured packet
def process_packet(packet):
    print("\n==============================")
    
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        # Check if the packet is TCP
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print("Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        
        # Check if the packet is UDP
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print("Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        
        # Other protocols
        else:
            print("Protocol: Other")

# Main sniffer execution
print("Sniffer Started... Press Ctrl+C to stop")

# Start sniffing (store=False ensures packets are not stored in memory)
sniff(prn=process_packet, store=False)
