from typing import List, Optional
from scapy.all import Ether, Packet


class PacketStore:
    """
    Stores packet data as raw bytes.
    Reconstructs Scapy packets safely on access.
    """
    def __init__(self, max_packets=5000):
        self._all_packets: List[bytes] = []
        self._max_packets = max_packets

    def add_packet(self, raw_packet: bytes):
        self._all_packets.append(raw_packet)
        if len(self._all_packets) > self._max_packets:
            self._all_packets.pop(0)

    def clear(self):
        self._all_packets.clear()

    def get_packet_count(self) -> int:
        return len(self._all_packets)

    def get_packet(self, index: int) -> Optional[Packet]:
        if 0 <= index < len(self._all_packets):
            try:
                return Ether(self._all_packets[index])  # ✅ FIX
            except Exception:
                return None
        return None

    def get_all_packets(self) -> List[Packet]:
        packets = []
        for raw in self._all_packets:
            try:
                packets.append(Ether(raw))              # ✅ FIX
            except Exception:
                pass
        return packets
