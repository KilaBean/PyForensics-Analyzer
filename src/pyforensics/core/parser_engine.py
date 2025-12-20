from scapy.all import IP, TCP, UDP, ICMP, ARP
from scapy.layers import http, dns

def parse_packet_summary(packet):
    """
    Parses a Scapy packet into a simple dictionary.
    FIX: Uses robust methods (packet.summary()) to avoid field access errors.
    """
    summary = {
        "No": "",
        "Time": packet.time,
        "Source": "N/A",
        "Destination": "N/A",
        "Protocol": "Other",
        "Length": len(packet),
        "Info": packet.summary()
    }

    if IP in packet:
        summary["Source"] = packet[IP].src
        summary["Destination"] = packet[IP].dst
    elif ARP in packet:
        summary["Source"] = packet[ARP].psrc
        summary["Destination"] = packet[ARP].pdst

    if packet.haslayer(http.HTTPRequest) or packet.haslayer(http.HTTPResponse):
        summary["Protocol"] = "HTTP"
    elif packet.haslayer(dns.DNS):
        summary["Protocol"] = "DNS"
    elif packet.haslayer(TCP):
        summary["Protocol"] = "TCP"
    elif packet.haslayer(UDP):
        summary["Protocol"] = "UDP"
    elif packet.haslayer(ICMP):
        summary["Protocol"] = "ICMP"
    elif packet.haslayer(ARP):
        summary["Protocol"] = "ARP"
    elif packet.haslayer(IP):
        summary["Protocol"] = "IP"
    
    return summary