from typing import List, Dict, Tuple, Any
from scapy.all import IP, TCP, UDP, ICMP
from collections import defaultdict

def analyze_conversations(packets: List) -> List[Dict[str, Any]]:
    """Analyzes packets to find conversations between endpoints."""
    conv_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
    
    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            # Create a canonical key for the conversation (sorted endpoints)
            key = tuple(sorted((src, dst)))
            
            conv_stats[key]["packets"] += 1
            conv_stats[key]["bytes"] += len(pkt)

    # Convert to a list of dictionaries for the UI
    conversations = []
    for (a, b), stats in conv_stats.items():
        conversations.append({
            "Endpoints": f"{a} <-> {b}",
            "A": a,
            "B": b,
            "Packets": stats["packets"],
            "Bytes": stats["bytes"],
        })
    
    # Sort by packets descending
    conversations.sort(key=lambda x: x["Packets"], reverse=True)
    return conversations