import os
from PySide6.QtCore import QObject, Signal
from scapy.utils import RawPcapReader  # <--- Faster, safer reader

class FileLoaderWorker(QObject):
    finished = Signal(list) 
    error = Signal(str)
    progress = Signal(int)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        self._is_running = True

    def run(self):
        if not os.path.exists(self.file_path):
            self.error.emit(f"File not found: {self.file_path}")
            return

        try:
            total_size = os.path.getsize(self.file_path)
        except OSError:
            total_size = 0

        loaded_packets_bytes = []
        current_pos = 0
        last_reported_progress = -1
        
        try:
            # RawPcapReader reads the file structure without parsing protocols.
            # This prevents hangs on malformed packets and is extremely fast.
            # It yields (raw_data, packet_metadata).
            reader = RawPcapReader(self.file_path)
            
            try:
                for pkt_data, metadata in reader:
                    if not self._is_running:
                        break

                    # pkt_data is already bytes, no conversion needed
                    loaded_packets_bytes.append(pkt_data)
                    
                    # Approximate position tracking (Packet Len + Pcap Header Overhead)
                    current_pos += len(pkt_data) + 16 

                    if total_size > 0:
                        percent = int((current_pos / total_size) * 100)
                        # OPTIMIZATION: Only emit if percentage CHANGED.
                        # This prevents flooding the GUI thread with thousands of signals.
                        if percent > last_reported_progress:
                            self.progress.emit(percent)
                            last_reported_progress = percent
            
            except Exception as e:
                # If a packet is truly corrupt, RawPcapReader raises an error.
                # We catch it, stop reading, but KEEP what we loaded so far.
                print(f"Warning: Stopped reading early due to corrupt packet: {e}")
            
            finally:
                reader.close()

            if self._is_running:
                self.progress.emit(100)
                self.finished.emit(loaded_packets_bytes)

        except Exception as e:
            self.error.emit(f"Error opening file: {str(e)}")

    def stop(self):
        """Stops the loop if Cancel is pressed"""
        self._is_running = False