from scapy.all import IP, TCP, sniff

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        protocol_name = get_protocol_name(proto)

        if is_malicious(packet):
            print(f"Malicious Packet Detected - Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol_name}")
        else:
            print(f"Safe Packet Detected - Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol_name}")

def get_protocol_name(proto):
    if proto == 1:
        return "ICMP"
    elif proto == 6:
        return "TCP"
    elif proto == 17:
        return "UDP"
    else:
        return "Unknown"

def is_malicious(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:            
        return True
    else:
        return False

sniff(prn=packet_callback, store=0)
