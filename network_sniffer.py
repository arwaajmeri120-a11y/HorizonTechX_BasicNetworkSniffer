from scapy.all import sniff
from scapy.layers.inet import IP

packet_count = 0

def packet_callback(packet):
    global packet_count

    if packet.haslayer(IP):
        packet_count += 1

        protocol = packet[IP].proto

        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = str(protocol)

        print("=" * 50)
        print(f"Packet No      : {packet_count}")
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")
        print(f"Protocol       : {protocol_name}")

print("Network Sniffer Started...")
print("Press Ctrl + C to Stop\n")
sniff(prn=packet_callback, store=False)