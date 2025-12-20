import sys
import os
import platform
import socket
import psutil
import datetime

from PySide6.QtWidgets import (
    QWidget, QGridLayout, QFrame, QLabel, QVBoxLayout, QApplication
)
from PySide6.QtCore import QTimer
import pyqtgraph as pg

# Ensure we can import the global theme if needed, 
# but we will apply specific styling here for the cards.
class DashboardTab(QWidget):
    def __init__(self):
        super().__init__()

        # --- System Monitoring Setup ---
        self.start_time = datetime.datetime.now()
        try:
            self.prev_bytes_sent = psutil.net_io_counters().bytes_sent
            self.prev_bytes_recv = psutil.net_io_counters().bytes_recv
        except Exception as e:
            print(f"Error initializing psutil: {e}")
            self.prev_bytes_sent = 0
            self.prev_bytes_recv = 0

        self.layout = QGridLayout()
        self.setLayout(self.layout)

        # 1. System Info Card
        self.card1 = self.create_card("System Info", self.get_system_info())
        self.layout.addWidget(self.card1, 0, 0)

        # 2. Network Stats Card
        self.net_stat_label = QLabel()
        self.card2 = self.create_card("Network Stats", self.net_stat_label)
        self.layout.addWidget(self.card2, 0, 1)

        # 3. Interfaces Card
        self.card3 = self.create_card("Interfaces", self.get_interfaces())
        self.layout.addWidget(self.card3, 1, 0)

        # 4. App Status Card
        self.status_label = QLabel()
        self.card4 = self.create_card("App Status", self.status_label)
        self.layout.addWidget(self.card4, 1, 1)

        # 5. Bandwidth Chart
        self.bandwidth_plot = pg.PlotWidget()
        
        # Modern Dark Theme Styling for the Plot
        self.bandwidth_plot.setBackground('#1e1e1e')
        self.bandwidth_plot.setTitle("Live Bandwidth Usage (KB/s)", color='#e0e0e0')
        self.bandwidth_plot.showGrid(x=True, y=True, alpha=0.3)
        self.bandwidth_plot.setLabel("left", "Speed", color='#e0e0e0')
        self.bandwidth_plot.setLabel("bottom", "Time", "s", color='#e0e0e0')
        self.bandwidth_plot.getAxis('left').setPen('#e0e0e0')
        self.bandwidth_plot.getAxis('bottom').setPen('#e0e0e0')

        self.bandwidth_line = self.bandwidth_plot.plot([], [], pen=pg.mkPen(color='#00ffcc', width=2))
        self.bandwidth_x = []
        self.bandwidth_y = []

        self.layout.addWidget(self.bandwidth_plot, 2, 0, 1, 2)

        # Update Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(2000) # Update every 2 seconds

    def create_card(self, title, content_widget):
        """Creates a styled card widget."""
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        
        # Styling to match the Dark Theme
        frame.setStyleSheet("""
            QFrame {
                background-color: #252526;
                color: #e0e0e0;
                border-radius: 8px;
                border: 1px solid #3e3e42;
            }
            QLabel {
                background-color: transparent;
                color: #e0e0e0;
                font-size: 13px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Title styling
        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #007acc;")
        layout.addWidget(title_label)
        
        layout.addWidget(content_widget)
        frame.setLayout(layout)
        return frame

    def get_system_info(self):
        try:
            os_name = platform.system()
            hostname = socket.gethostname()
            # Try to get local IP
            ip_address = "127.0.0.1"
            try:
                ip_address = socket.gethostbyname(hostname)
            except:
                pass
            
            label = QLabel(f"OS: {os_name}\nHostname: {hostname}\nIP Address: {ip_address}")
            return label
        except Exception as e:
            return QLabel("Error retrieving system info")

    def get_interfaces(self):
        try:
            interfaces = psutil.net_if_addrs()
            # Limit display to first 5 interfaces to avoid overflow
            iface_names = list(interfaces.keys())[:5]
            label = QLabel("\n".join(iface_names))
            return label
        except Exception as e:
            return QLabel("Error retrieving interfaces")

    def update_stats(self):
        try:
            stats = psutil.net_io_counters()
            delta_sent = stats.bytes_sent - self.prev_bytes_sent
            delta_recv = stats.bytes_recv - self.prev_bytes_recv

            # Calculate KB/s
            kbps = (delta_sent + delta_recv) / 1024 

            self.prev_bytes_sent = stats.bytes_sent
            self.prev_bytes_recv = stats.bytes_recv

            # Update Network Stats Text
            self.net_stat_label.setText(
                f"Sent: {stats.bytes_sent:,} bytes\n"
                f"Received: {stats.bytes_recv:,} bytes\n"
                f"Bandwidth: {kbps:.2f} KB/s"
            )

            # Update App Status Text
            uptime = datetime.datetime.now() - self.start_time
            self.status_label.setText(f"Uptime: {str(uptime).split('.')[0]}\nStatus: Active")

            # Update Chart
            current_time = int((datetime.datetime.now() - self.start_time).total_seconds())
            self.bandwidth_x.append(current_time)
            self.bandwidth_y.append(kbps)

            # Keep only last 60 data points (2 minutes)
            if len(self.bandwidth_x) > 60:
                self.bandwidth_x = self.bandwidth_x[-60:]
                self.bandwidth_y = self.bandwidth_y[-60:]

            self.bandwidth_line.setData(self.bandwidth_x, self.bandwidth_y)
            
        except Exception as e:
            print(f"Error updating dashboard stats: {e}")