from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    print("\n==============================")

    # IP layer check
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"Source IP      : {ip.src}")
        print(f"Destination IP : {ip.dst}")

    # Protocol detection
    protocol = "Other"

    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"

    print("Protocol       :", protocol)

    # Payload extraction
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        print("Payload        :", payload[:100])
    else:
        print("Payload        : None")

print("Live Network Sniffer Started... (Press Ctrl + C to stop)")
sniff(prn=process_packet, store=False)