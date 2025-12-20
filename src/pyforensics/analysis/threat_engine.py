# src/pyforensics/analysis/threat_engine.py
from scapy.all import IP, TCP, UDP, Raw
from pyforensics.analysis.threat_rules import MALICIOUS_IPS, SIGNATURES
import time

class ThreatEngine:
    """
    Analyzes packets against strict rulesets.
    """
    def analyze(self, packet):
        """
        Returns a dictionary representing an Alert if a threat is found.
        Returns None if clean.
        """
        # 1. IP REPUTATION CHECK
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            
            if src in MALICIOUS_IPS:
                return self._create_alert("IP Reputation", f"Source IP {src} is blacklisted", "High", src, dst)
            if dst in MALICIOUS_IPS:
                return self._create_alert("IP Reputation", f"Destination IP {dst} is blacklisted", "High", src, dst)

        # 2. PAYLOAD SIGNATURE CHECK
        # We only check packets that have a Raw payload (data)
        if packet.haslayer(Raw):
            try:
                payload = bytes(packet[Raw].load)
                
                for sig in SIGNATURES:
                    # Check Protocol (Optimization)
                    if sig['proto'] == "TCP" and not packet.haslayer(TCP): continue
                    if sig['proto'] == "UDP" and not packet.haslayer(UDP): continue

                    # Check Patterns
                    for pattern in sig['pattern']:
                        if pattern in payload:
                            # Found a match!
                            src = packet[IP].src if IP in packet else "?"
                            dst = packet[IP].dst if IP in packet else "?"
                            return self._create_alert(
                                sig['name'], 
                                f"Pattern match: {pattern.decode('utf-8', 'ignore')}", 
                                sig['severity'], 
                                src, dst
                            )
            except Exception:
                # Payload decoding issues or partial packets
                pass

        return None

    def _create_alert(self, title, details, severity, src, dst):
        return {
            "timestamp": time.strftime("%H:%M:%S"),
            "title": title,
            "details": details,
            "severity": severity,
            "src": src,
            "dst": dst
        }