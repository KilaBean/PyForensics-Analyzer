# src/pyforensics/analysis/threat_rules.py

# 1. IP BLACKLIST (Reputation)
# In a real app, you would load this from a CSV/Feed (e.g., AbuseIPDB).
# We include some common public DNS/Test IPs here just for testing visibility.
MALICIOUS_IPS = {
    "192.168.1.200", # Example Local Bad Actor
    "45.33.32.156",  # Example C2 (Fictional)
    # Add actual known bad IPs here
}

# 2. PAYLOAD SIGNATURES (Strict)
# These check the raw content of TCP/UDP packets.
SIGNATURES = [
    {
        "id": 1001,
        "name": "SQL Injection Attempt",
        "pattern": [b"UNION SELECT", b"OR 1=1", b"information_schema"],
        "severity": "High",
        "proto": "TCP"
    },
    {
        "id": 1002,
        "name": "Command Injection / RCE",
        "pattern": [b"/bin/sh", b"cmd.exe", b"wget http", b"curl http"],
        "severity": "High",
        "proto": "TCP"
    },
    {
        "id": 1003,
        "name": "Directory Traversal",
        "pattern": [b"../..", b"etc/passwd", b"boot.ini"],
        "severity": "Medium",
        "proto": "TCP"
    },
    {
        "id": 1004,
        "name": "XSS Script Injection",
        "pattern": [b"<script>", b"javascript:", b"onerror="],
        "severity": "Medium",
        "proto": "TCP"
    },
    {
        "id": 1005,
        "name": "Cleartext Credentials (Basic Auth)",
        "pattern": [b"Authorization: Basic"],
        "severity": "Low",
        "proto": "TCP"
    }
]