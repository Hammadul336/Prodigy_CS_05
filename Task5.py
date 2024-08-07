from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Determine protocol
        if protocol == 6:
            proto_name = 'TCP'
        elif protocol == 17:
            proto_name = 'UDP'
        else:
            proto_name = 'Other'

        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {proto_name}")

        # Check for payload
        if TCP in packet or UDP in packet:
            payload = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload)
            print(f"Payload: {payload}\n")

# Start sniffing
print("Starting packet sniffing...")
sniff(prn=packet_callback, store=0)
