Here is a professional, summarized README.md file content based on your report. You can copy and paste this directly into your GitHub repository.

PyForensics Analyzer

An Advanced Network Forensics Analysis Tool with Integrated Threat Intelligence.

📖 Overview

PyForensics Analyzer is a comprehensive desktop application designed to bridge the gap between raw packet capture and actionable security intelligence. Unlike standard packet sniffers that overwhelm analysts with raw data, this tool integrates a custom Threat Intelligence Engine and Geo-Location services directly into the workflow.

Built for security professionals and researchers, it offers real-time deep packet inspection (DPI), automated detection of malicious traffic (such as SQL injections and XSS), and immediate visual alerting for network anomalies.

🚀 Key Features
🛡️ Threat Intelligence & Security

Automated Detection: Scans TCP/UDP payloads for known attack signatures (SQLi, RCE, Directory Traversal).

Heuristic Analysis: Flags anomalies like cleartext credential transmission.

Visual Alerting: High-priority threats are instantly highlighted in Red, with detailed logs generated in a dedicated dock.

📡 Real-Time Capture & Analysis

Smart Sniffing: Multi-threaded capture engine supporting Start, Stop, and Pause (buffering) without data loss.

Interface Detection: Automatically maps system GUIDs to friendly names (e.g., "Wi-Fi").

Wireshark-Style Filters: translation layer converts user-friendly syntax (e.g., ip.addr == 192.168.1.5) into BPF for the capture engine.

🌍 Geo-Location Integration

Integrated MaxMind GeoLite2 database.

Performs offline lookups to display Country, City, and Coordinates for Source/Destination IPs, aiding in cross-border traffic analysis.

📊 Data Visualization & Export

Deep Inspection: Hierarchical tree view of packet headers (Ethernet, IP, TCP) and raw Hex/ASCII dumps.

I/O Graphs: Real-time visualization of network bandwidth and flow.

Export: Save analysis results to CSV and JSON formats or standard PCAP files.

📸 Screenshots
1. Main Interface

Professional Dashboard showing device, network info, and real-time capture controls.

![alt text](screenshots/main_interface.png)

2. Deep Inspection & Threat Intelligence

Layer-by-layer packet decoding with integrated Geo-Location lookup. Automated detection of malicious payloads (SQLi, RCE) is shown with instant visual alerting.

![alt text](screenshots/packet_details.png)

🛠️ Technology Stack
Component	Technology	Purpose
Core Logic	Python 3.10+	Backend processing and threading.
UI	PySide6 (Qt)	Modern, dark-themed responsive interface.
Networking	Scapy	Packet sniffing, parsing, and manipulation.
Location	GeoIP2	Physical location mapping.
System	Psutil	Interface enumeration.
Graphs	Matplotlib	Real-time traffic visualization.
⚙️ How to Run
Prerequisites

Python 3.10+ installed.

Npcap (Required for Windows users to capture packets). Download Npcap.

MaxMind GeoLite2 Database: Due to licensing, the .mmdb file is not included in the repo.

Installation Steps

Clone the Repository

code
Bash
download
content_copy
expand_less
git clone https://github.com/KilaBean/PyForensics-Analyzer.git
cd PyForensics-Analyzer

Create a Virtual Environment (Recommended)

code
Bash
download
content_copy
expand_less
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

Install Dependencies

code
Bash
download
content_copy
expand_less
pip install -r requirements.txt

Setup GeoIP Database

Download GeoLite2-City.mmdb from MaxMind.

Place the file in the root directory or inside src/pyforensics/data/.

Run the Application

code
Bash
download
content_copy
expand_less
python main.py

🔮 Future Roadmap

TLS Decryption: Support for key-log files to decrypt HTTPS traffic.

Remote Capture: SSH tunneling to capture from remote sensors.

Machine Learning: Anomaly-based threat detection for patterns that bypass signatures.