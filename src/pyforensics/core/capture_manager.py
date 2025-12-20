from PySide6.QtCore import QObject, Signal, QThread
from scapy.all import sniff, conf, get_if_list
import psutil

class CaptureManager(QObject):
    packet_captured = Signal(bytes)
    capture_stopped = Signal()
    error_occurred = Signal(str)

    def __init__(self):
        super().__init__()
        self._running = False
        self._paused = False
        self._thread = None

    def get_readable_interfaces(self):
        """
        Returns interfaces as (Display Name, Scapy Interface Name).
        Uses psutil to find friendly names (e.g., "Wi-Fi") and matches them
        to Scapy interfaces via MAC Address.
        """
        interfaces = []
        
        # 1. Get Friendly Names & MACs from psutil
        # Format: {'00:11:22...': 'Wi-Fi', ...}
        mac_to_friendly = {}
        try:
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:  # AF_LINK is the MAC address layer
                        # Normalize MAC to lowercase/standard format if needed
                        mac = addr.address.lower().replace('-', ':')
                        mac_to_friendly[mac] = name
        except Exception:
            pass # psutil might fail on some restricted systems

        try:
            # 2. Iterate Scapy Interfaces
            if hasattr(conf, "ifaces"):
                for iface in conf.ifaces.values():
                    scapy_name = iface.name      # Often a GUID on Windows
                    scapy_mac = getattr(iface, "mac", "").lower()
                    description = getattr(iface, "description", scapy_name)

                    # Determine Display Name
                    # Priority: psutil Friendly Name > Scapy Description > Scapy Name
                    display_name = description
                    
                    if scapy_mac in mac_to_friendly:
                        friendly = mac_to_friendly[scapy_mac]
                        display_name = f"{friendly} ({description})"
                    
                    # Store tuple: (Display Text, Value used for sniffing)
                    interfaces.append((str(display_name), str(scapy_name)))

            # Fallback if Scapy conf is empty
            if not interfaces:
                for iface in get_if_list():
                    interfaces.append((str(iface), str(iface)))
                    
        except Exception as e:
            print(f"Warning: Could not list interfaces: {e}")
            if not interfaces:
                interfaces.append(("Default", "default"))
            
        return interfaces

    def set_paused(self, paused: bool):
        self._paused = paused

    def start_capture(self, iface, bpf_filter=""):
        if self._running:
            return

        self._running = True
        self._paused = False

        def _capture():
            while self._running:
                try:
                    sniff(
                        iface=iface,
                        filter=bpf_filter or None,
                        prn=self._process_packet,
                        timeout=0.5,
                        store=False
                    )
                except Exception as e:
                    self.error_occurred.emit(str(e))
                    self._running = False
            
            self.capture_stopped.emit()

        self._thread = QThread()
        self._thread.run = _capture
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _process_packet(self, pkt):
        if not self._running:
            return
        if not self._paused:
            self.packet_captured.emit(bytes(pkt))

    def stop_capture(self):
        self._running = False

    def cleanup(self):
        self._running = False
        if self._thread:
            try:
                if self._thread.isRunning():
                    self._thread.quit()
                    self._thread.wait()
            except RuntimeError:
                pass