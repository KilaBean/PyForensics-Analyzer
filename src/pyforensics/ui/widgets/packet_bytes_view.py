from PySide6.QtWidgets import QTextEdit
from PySide6.QtGui import QFont, QColor, QPalette
from scapy.all import Packet, hexdump

class PacketBytesView(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 9)) # Monospaced font
        self.setLineWrapMode(QTextEdit.NoWrap)
        self.packet = None
        
        # Modern Terminal Styling
        self.setStyleSheet("""
            QTextEdit {
                background-color: #121212;
                color: #00ff00;
                border: none;
            }
        """)

    def set_packet(self, packet: Packet):
        """Updates the view with the hex dump of a new packet."""
        self.packet = packet
        self.clear()
        if packet:
            # Use scapy's hexdump to generate the string
            hex_str = hexdump(packet, dump=True)
            self.setPlainText(hex_str)