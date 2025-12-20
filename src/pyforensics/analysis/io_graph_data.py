from typing import List, Dict, Tuple
from scapy.all import IP
from collections import defaultdict

def generate_io_graph_data(packets: List, interval: float = 1.0) -> Tuple[List[float], List[int]]:
    """
    Generates data for an I/O graph (packets per second).
    Returns a tuple of (timestamps, packet_counts).
    """
    if not packets:
        return [], []

    start_time = packets[0].time
    time_buckets = defaultdict(int)

    for pkt in packets:
        if IP in pkt:
            bucket = int((pkt.time - start_time) / interval)
            time_buckets[bucket] += 1

    if not time_buckets:
        return [], []
        
    timestamps = [start_time + i * interval for i in range(max(time_buckets.keys()) + 1)]
    packet_counts = [time_buckets.get(i, 0) for i in range(max(time_buckets.keys()) + 1)]
    
    return timestamps, packet_counts