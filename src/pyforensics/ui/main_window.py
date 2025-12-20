import sys
import os
import csv
import json
import datetime

# Ensure the project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QDockWidget,
    QTableView, QTreeWidget, QTreeWidgetItem, QPushButton, QComboBox,
    QToolBar, QHeaderView, QLineEdit, QFileDialog, QStatusBar, QLabel, QApplication,
    QProgressDialog, QMessageBox, QSizePolicy, QTabWidget, QStyledItemDelegate, QStyle
)
from PySide6.QtCore import Qt, QThread, QTimer, QSize, Signal, QObject
from PySide6.QtGui import QColor, QBrush

# Import Scapy components
from scapy.all import IP, Ether, TCP, UDP, ICMP, ARP
from scapy.layers import http, dns

# --- Import Custom Project Components ---
from pyforensics.core.capture_manager import CaptureManager
from pyforensics.core.geoip_manager import GeoIPManager
from pyforensics.data.packet_store import PacketStore
from pyforensics.ui.packet_model import PacketModel

# Import Widgets
from pyforensics.ui.widgets.packet_bytes_view import PacketBytesView
from pyforensics.ui.widgets.conversations_view import ConversationsView
from pyforensics.ui.widgets.io_graph_view import IOGraphView
from pyforensics.ui.widgets.dashboard_view import DashboardTab
from pyforensics.ui.file_loader_worker import FileLoaderWorker
from pyforensics.ui.widgets.threat_log_view import ThreatLogView

# Import Analysis
from pyforensics.analysis.conversation_analyzer import analyze_conversations
from pyforensics.analysis.io_graph_data import generate_io_graph_data
from pyforensics.analysis.threat_engine import ThreatEngine

# Import Theme & Colors
from pyforensics.ui.theme import STYLESHEET, PROTOCOL_COLORS


# --- WORKER FOR BACKGROUND THREAT ANALYSIS (Fixes Freeze) ---
class AnalysisWorker(QObject):
    finished = Signal(list, set)  # Returns (alerts_list, threat_row_indices)
    progress = Signal(int)

    def __init__(self, packets):
        super().__init__()
        self.packets = packets
        self.threat_engine = ThreatEngine()
        self._is_running = True

    def run(self):
        alerts = []
        threat_rows = set()
        total = len(self.packets)
        
        # Process in chunks to avoid locking GIL too long
        for i, raw_pkt in enumerate(self.packets):
            if not self._is_running:
                break
                
            try:
                # Heavy operation: Parsing + Regex matching
                scapy_pkt = Ether(raw_pkt)
                alert = self.threat_engine.analyze(scapy_pkt)
                
                if alert:
                    alerts.append(alert)
                    threat_rows.add(i)
            except Exception:
                pass
            
            # Update progress every 1%
            if total > 0 and i % (max(1, total // 100)) == 0:
                self.progress.emit(int((i / total) * 100))

        self.finished.emit(alerts, threat_rows)

    def stop(self):
        self._is_running = False


# --- CUSTOM DELEGATE FOR ROW COLORING ---
class ProtocolColorDelegate(QStyledItemDelegate):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.threat_rows = set() 

    def set_threat_rows(self, rows):
        self.threat_rows = rows

    def paint(self, painter, option, index):
        painter.save()

        if option.state & QStyle.State_Selected:
            super().paint(painter, option, index)
        else:
            # Priority 1: Threats (Red)
            if index.row() in self.threat_rows:
                painter.fillRect(option.rect, QColor("#4a0f0f"))
            # Priority 2: Protocols
            else:
                protocol_index = index.sibling(index.row(), 4)
                protocol_name = protocol_index.data()
                if protocol_name and protocol_name in PROTOCOL_COLORS:
                    color = QColor(PROTOCOL_COLORS[protocol_name])
                    painter.fillRect(option.rect, color)
            
            super().paint(painter, option, index)

        painter.restore()


# --- MAIN WINDOW ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setStyleSheet(STYLESHEET)
        self.setWindowTitle("PyForensics Analyzer")
        self.setGeometry(100, 100, 1600, 1000)
        self.setIconSize(QSize(24, 24))

        # --- Core Components ---
        self.packet_store = PacketStore()
        self.capture_manager = None
        self.file_loader_thread = None
        self.file_loader_worker = None
        self.analysis_thread = None  # Thread for analysis
        
        self.geoip_manager = GeoIPManager()
        self.threat_engine = ThreatEngine()
        self.threat_rows = set()
        
        # State Tracking
        self.current_file_path = None

        # --- UI Setup ---
        self._setup_docks()
        self._setup_status_bar()
        self._setup_ui()
        self._setup_capture_manager()

        # --- Initial Dock State ---
        self.conversations_dock.hide()
        self.io_graph_dock.hide()
        self.threat_dock.hide() 

        # --- Tab Logic ---
        self.tabs.currentChanged.connect(self.on_tab_changed)

        # Timer for live analysis updates
        self.analysis_timer = QTimer()
        self.analysis_timer.setSingleShot(True)
        self.analysis_timer.timeout.connect(self.update_analysis_views)

    def _setup_ui(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        # Interface
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(200)
        toolbar.addWidget(self.interface_combo)

        # Controls
        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.trigger_start_capture)
        toolbar.addWidget(self.start_button)

        self.pause_button = QPushButton("Pause")
        self.pause_button.setCheckable(True)
        self.pause_button.setEnabled(False)
        self.pause_button.clicked.connect(self.toggle_pause_capture)
        toolbar.addWidget(self.pause_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        toolbar.addWidget(self.stop_button)

        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_capture_data)
        toolbar.addWidget(self.clear_button)

        toolbar.addSeparator()

        # Filters
        self.protocol_filter_combo = QComboBox()
        self.protocol_filter_combo.addItems([
            "All Protocols", "TCP", "UDP", "ICMP", "ARP", "HTTP", "DNS"
        ])
        self.protocol_filter_combo.setMinimumWidth(120)
        toolbar.addWidget(self.protocol_filter_combo)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter: ip.addr == 1.2.3.4 || tcp.port == 80")
        self.filter_input.setMaximumWidth(400)
        self.filter_input.returnPressed.connect(self.apply_filter)
        toolbar.addWidget(self.filter_input)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        toolbar.addWidget(spacer)

        self._create_menu_bar()

        # --- Central Tabs ---
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # Index 0: Dashboard
        self.dashboard_tab = DashboardTab()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")

        # Index 1: Analysis
        self.analysis_tab_widget = QWidget()
        analysis_layout = QHBoxLayout(self.analysis_tab_widget)
        analysis_layout.setContentsMargins(0, 0, 0, 0)

        main_splitter = QSplitter(Qt.Horizontal)
        analysis_layout.addWidget(main_splitter)

        # Left: Packet List
        self.packet_model = PacketModel(self.packet_store)
        self.packet_list = QTableView()
        self.packet_list.setModel(self.packet_model)
        self.packet_list.setSelectionBehavior(QTableView.SelectRows)
        self.packet_list.setEditTriggers(QTableView.NoEditTriggers)
        self.packet_list.setSortingEnabled(True)
        self.packet_list.verticalHeader().setVisible(False)
        
        self.packet_delegate = ProtocolColorDelegate(self.packet_list)
        self.packet_list.setItemDelegate(self.packet_delegate)

        header = self.packet_list.horizontalHeader()
        for i in range(6):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.Stretch)

        main_splitter.addWidget(self.packet_list)

        # Right: Details & Bytes
        right_splitter = QSplitter(Qt.Vertical)
        self.packet_details = QTreeWidget()
        self.packet_details.setHeaderLabels(["Field", "Value"])
        right_splitter.addWidget(self.packet_details)

        self.packet_bytes = PacketBytesView()
        right_splitter.addWidget(self.packet_bytes)

        main_splitter.addWidget(right_splitter)
        self.tabs.addTab(self.analysis_tab_widget, "Analysis")

        self.packet_list.selectionModel().selectionChanged.connect(self.on_packet_selected)
        self.setCentralWidget(self.tabs)

    def _setup_docks(self):
        # 1. Conversations
        self.conversations_view = ConversationsView()
        self.conversations_dock = QDockWidget("Conversations", self)
        self.conversations_dock.setWidget(self.conversations_view)
        self.addDockWidget(Qt.RightDockWidgetArea, self.conversations_dock)

        # 2. IO Graph
        self.io_graph_view = IOGraphView()
        self.io_graph_dock = QDockWidget("I/O Graph", self)
        self.io_graph_dock.setWidget(self.io_graph_view)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.io_graph_dock)

        # 3. Threat Log (Dockable)
        self.threat_log_view = ThreatLogView()
        self.threat_dock = QDockWidget("Threat Intelligence Log", self)
        self.threat_dock.setWidget(self.threat_log_view)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.threat_dock)

    def on_tab_changed(self, index):
        if index == 1:
            self.threat_dock.show()
        else:
            self.threat_dock.hide()

    def _create_menu_bar(self):
        menubar = self.menuBar()
        
        # FILE MENU
        file_menu = menubar.addMenu("&File")
        file_menu.addAction("&Open...", self.open_capture_file, "Ctrl+O")
        file_menu.addAction("&Save", self.save_capture_file, "Ctrl+S")
        file_menu.addAction("Save &As...", self.save_capture_file_as, "Ctrl+Shift+S")
        file_menu.addSeparator()
        
        # EXPORT SUBMENU
        export_menu = file_menu.addMenu("&Export")
        export_menu.addAction("Export to &CSV", self.export_to_csv)
        export_menu.addAction("Export to &JSON", self.export_to_json)
        
        file_menu.addSeparator()
        file_menu.addAction("E&xit", self.close, "Ctrl+Q")

        # VIEW MENU
        view_menu = menubar.addMenu("&View")
        view_menu.addAction(self.conversations_dock.toggleViewAction())
        view_menu.addAction(self.io_graph_dock.toggleViewAction())
        view_menu.addAction(self.threat_dock.toggleViewAction())

    def _setup_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.packets_label = QLabel("Packets: 0")
        self.status_bar.addPermanentWidget(self.packets_label)

    def _setup_capture_manager(self):
        self.capture_manager = CaptureManager()
        self.capture_manager.packet_captured.connect(self.on_packet_captured)
        self.capture_manager.capture_stopped.connect(self.on_capture_stopped)
        self.capture_manager.error_occurred.connect(self.on_capture_error)

        for name, iface in self.capture_manager.get_readable_interfaces():
            self.interface_combo.addItem(name, iface)

        if self.interface_combo.count() > 0:
            self.interface_combo.setCurrentIndex(0)

    # ------------------------------------------------------------------
    # Clear & Reset Logic
    # ------------------------------------------------------------------
    def clear_capture_data(self):
        if self.packet_store.get_packet_count() == 0:
            QMessageBox.information(self, "Clear", "No packets to clear.")
            return

        reply = QMessageBox.question(
            self, 
            "Clear Packets", 
            "Are you sure you want to clear all captured data?\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self._reset_capture_state()
            QMessageBox.information(self, "Cleared", "All packet data cleared.")

    def _reset_capture_state(self):
        if self.stop_button.isEnabled():
            self.stop_capture()

        self.packet_store.clear()
        self.threat_rows.clear()
        self.packet_delegate.set_threat_rows(self.threat_rows)
        self.threat_log_view.setRowCount(0)
        self.packet_model.layoutChanged.emit()
        self.packet_details.clear()
        self.packet_bytes.clear()
        self.conversations_view.clear()
        self.io_graph_view.update_plot([], [])
        self.update_status_bar()
        self.current_file_path = None

    # ------------------------------------------------------------------
    # Capture Logic
    # ------------------------------------------------------------------
    def _get_combined_bpf(self):
        proto = self.protocol_filter_combo.currentText()
        proto_bpf = ""
        if proto == "TCP": proto_bpf = "tcp"
        elif proto == "UDP": proto_bpf = "udp"
        elif proto == "ICMP": proto_bpf = "icmp"
        elif proto == "ARP": proto_bpf = "arp"
        elif proto == "HTTP": proto_bpf = "tcp port 80 or tcp port 443"
        elif proto == "DNS": proto_bpf = "port 53"
        
        raw_text = self.filter_input.text().strip()
        text_bpf = self._translate_wireshark_to_bpf(raw_text)
        
        if proto_bpf and text_bpf: return f"({proto_bpf}) and ({text_bpf})"
        elif proto_bpf: return proto_bpf
        else: return text_bpf

    def _translate_wireshark_to_bpf(self, ws_filter):
        if not ws_filter: return ""
        f = ws_filter.lower().strip()
        replacements = [
            ("ip.addr", "host"), ("ip.src", "src host"), ("ip.dst", "dst host"),
            ("tcp.port", "tcp port"), ("udp.port", "udp port"),
            ("==", ""), ("&&", "and"), ("||", "or")
        ]
        for old, new in replacements: f = f.replace(old, new)
        return " ".join(f.split())

    def trigger_start_capture(self):
        if self.interface_combo.currentIndex() == -1:
            QMessageBox.warning(self, "Interface Error", "No interface selected!")
            return

        self._reset_capture_state()
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.pause_button.setEnabled(True)
        self.pause_button.setChecked(False)
        self.pause_button.setText("Pause")
        self.clear_button.setEnabled(False)
        
        self.interface_combo.setEnabled(False)
        self.protocol_filter_combo.setEnabled(False)
        self.filter_input.setEnabled(False)

        self.tabs.setCurrentIndex(1)
        self.threat_dock.show()

        iface = self.interface_combo.currentData()
        bpf = self._get_combined_bpf()
        self.capture_manager.start_capture(iface, bpf_filter=bpf)

    def apply_filter(self):
        if self.interface_combo.currentIndex() == -1: return
        bpf = self._get_combined_bpf()
        self.capture_manager.stop_capture()
        iface = self.interface_combo.currentData()
        self.capture_manager.start_capture(iface, bpf_filter=bpf)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.pause_button.setEnabled(True)
        self.clear_button.setEnabled(False)
        self.interface_combo.setEnabled(False)
        self.protocol_filter_combo.setEnabled(False)
        self.filter_input.setEnabled(False)

    def toggle_pause_capture(self):
        is_paused = self.pause_button.isChecked()
        self.pause_button.setText("Resume" if is_paused else "Pause")
        self.capture_manager.set_paused(is_paused)

    def stop_capture(self):
        self.capture_manager.stop_capture()

    def on_capture_stopped(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.pause_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.interface_combo.setEnabled(True)
        self.protocol_filter_combo.setEnabled(True)
        self.filter_input.setEnabled(True)
        self.update_analysis_views()

    def on_capture_error(self, message):
        QMessageBox.critical(self, "Capture Error", message)
        self.on_capture_stopped()

    def on_packet_captured(self, raw_bytes: bytes):
        self.packet_store.add_packet(raw_bytes)
        new_row_index = self.packet_store.get_packet_count() - 1
        
        try:
            scapy_pkt = Ether(raw_bytes)
            alert = self.threat_engine.analyze(scapy_pkt)
            if alert:
                self.threat_log_view.add_alert(alert)
                self.threat_rows.add(new_row_index)
                self.packet_delegate.set_threat_rows(self.threat_rows)
        except Exception:
            pass

        self.packet_model.packet_added()
        self.update_status_bar()

    def update_status_bar(self):
        self.packets_label.setText(f"Packets: {self.packet_store.get_packet_count()}")

    def on_packet_selected(self):
        indexes = self.packet_list.selectionModel().selectedRows()
        if not indexes:
            self.packet_details.clear()
            self.packet_bytes.set_packet(None)
            return

        packet = self.packet_store.get_packet(indexes[0].row())
        self.packet_bytes.set_packet(packet)
        self.packet_details.clear()

        if packet:
            for layer in packet.layers():
                layer_item = QTreeWidgetItem([layer.name, ""])
                for field in layer.fields_desc:
                    try:
                        val = packet.getfieldval(field.name)
                        layer_item.addChild(QTreeWidgetItem([field.name, repr(val)]))
                    except: pass
                self.packet_details.addTopLevelItem(layer_item)

            if IP in packet and self.geoip_manager.available:
                geo_root = QTreeWidgetItem(["Geo Location", ""])
                geo_root.setForeground(0, QBrush(QColor("#007acc")))
                src = packet[IP].src
                dst = packet[IP].dst
                src_d = self.geoip_manager.lookup(src)
                if src_d:
                    n = QTreeWidgetItem([f"Source: {src}", src_d['summary']])
                    n.addChild(QTreeWidgetItem(["Coords", f"{src_d['lat']}, {src_d['lon']}"]))
                    geo_root.addChild(n)
                dst_d = self.geoip_manager.lookup(dst)
                if dst_d:
                    n = QTreeWidgetItem([f"Destination: {dst}", dst_d['summary']])
                    n.addChild(QTreeWidgetItem(["Coords", f"{dst_d['lat']}, {dst_d['lon']}"]))
                    geo_root.addChild(n)
                if geo_root.childCount() > 0:
                    self.packet_details.addTopLevelItem(geo_root)
                    geo_root.setExpanded(True)

        self.packet_details.expandAll()

    def update_analysis_views(self):
        packets = self.packet_store.get_all_packets()
        if not packets: return
        self.conversations_view.populate(analyze_conversations(packets))
        t, c = generate_io_graph_data(packets)
        self.io_graph_view.update_plot(t, c)

    # ------------------------------------------------------------------
    # File I/O (Import, Save, Export)
    # ------------------------------------------------------------------
    def open_capture_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Capture File", "", "Pcap Files (*.pcap *.pcapng)")
        if not file_name: return
        
        self._reset_capture_state()
        self.current_file_path = file_name
        
        self.progress_dialog = QProgressDialog("Loading capture file...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.setMinimumDuration(0)
        self.progress_dialog.setValue(0)
        self.progress_dialog.show()

        self.file_loader_thread = QThread()
        self.file_loader_worker = FileLoaderWorker(file_name)
        self.file_loader_worker.moveToThread(self.file_loader_thread)

        self.file_loader_worker.progress.connect(self.progress_dialog.setValue)
        
        self.file_loader_worker.finished.connect(lambda packets: self.on_file_loaded(packets, file_name))
        self.file_loader_worker.finished.connect(self.progress_dialog.close)
        self.file_loader_worker.finished.connect(self.file_loader_thread.quit)
        
        self.file_loader_worker.error.connect(self.on_file_load_error)
        self.file_loader_worker.error.connect(self.progress_dialog.close)
        self.file_loader_worker.error.connect(self.file_loader_thread.quit)
        
        self.file_loader_thread.finished.connect(self.file_loader_thread.deleteLater)
        self.file_loader_thread.finished.connect(self.file_loader_worker.deleteLater)
        
        self.progress_dialog.canceled.connect(self.file_loader_worker.stop)
        self.progress_dialog.canceled.connect(self.file_loader_thread.quit)

        self.file_loader_thread.started.connect(self.file_loader_worker.run)
        self.file_loader_thread.start()

    def on_file_loaded(self, packets, file_name):
        # 1. Fast Load (Add packets to store)
        for p in packets: 
            self.packet_store.add_packet(p)
        
        self.packet_model.layoutChanged.emit()
        self.update_status_bar()
        self.setWindowTitle(f"PyForensics Analyzer - {os.path.basename(file_name)}")
        
        # 2. Background Threat Analysis (Prevents Freeze)
        self.analysis_dialog = QProgressDialog("Analyzing packets for threats...", "Stop", 0, 100, self)
        self.analysis_dialog.setWindowModality(Qt.WindowModal)
        self.analysis_dialog.setMinimumDuration(0)
        self.analysis_dialog.setValue(0)
        self.analysis_dialog.show()

        self.analysis_thread = QThread()
        self.analysis_worker = AnalysisWorker(packets)
        self.analysis_worker.moveToThread(self.analysis_thread)

        self.analysis_worker.progress.connect(self.analysis_dialog.setValue)
        self.analysis_worker.finished.connect(self.on_analysis_finished)
        self.analysis_worker.finished.connect(self.analysis_dialog.close)
        self.analysis_worker.finished.connect(self.analysis_thread.quit)
        
        self.analysis_thread.finished.connect(self.analysis_thread.deleteLater)
        self.analysis_thread.finished.connect(self.analysis_worker.deleteLater)
        
        self.analysis_dialog.canceled.connect(self.analysis_worker.stop)
        self.analysis_dialog.canceled.connect(self.analysis_thread.quit)

        self.analysis_thread.started.connect(self.analysis_worker.run)
        self.analysis_thread.start()

    def on_analysis_finished(self, alerts, threat_rows):
        """Called when background threat analysis is done."""
        # 1. Update Threat Log
        for alert in alerts:
            self.threat_log_view.add_alert(alert)
        
        # 2. Update Table Coloring
        self.threat_rows = threat_rows
        self.packet_delegate.set_threat_rows(self.threat_rows)
        self.packet_model.layoutChanged.emit() # Refresh table to show colors
        
        # 3. Update Visuals
        self.update_analysis_views()
        self.statusBar().showMessage(f"Loaded and Analyzed {self.packet_store.get_packet_count()} packets", 5000)
        QMessageBox.information(
            self, 
            "Import Successful", 
            f"Successfully imported and analyzed {self.packet_store.get_packet_count()} packets."
        )

    def on_file_load_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self.statusBar().showMessage(f"Error loading file: {message}", 5000)

    def save_capture_file(self):
        if not self.packet_store.get_packet_count():
            QMessageBox.warning(self, "Save Error", "No packets to save!")
            return

        if self.current_file_path:
            self._write_packets_to_file(self.current_file_path)
        else:
            self.save_capture_file_as()

    def save_capture_file_as(self):
        if not self.packet_store.get_packet_count():
            QMessageBox.warning(self, "Save Error", "No packets to save!")
            return

        file_name, _ = QFileDialog.getSaveFileName(self, "Save Capture File", "", "Pcap Files (*.pcap)")
        if not file_name: return
        
        if not file_name.endswith('.pcap'):
            file_name += '.pcap'
            
        self.current_file_path = file_name
        self._write_packets_to_file(file_name)

    def _write_packets_to_file(self, file_path):
        from scapy.all import wrpcap
        try:
            wrpcap(file_path, self.packet_store.get_all_packets())
            self.statusBar().showMessage(f"Saved to {file_path}", 3000)
            QMessageBox.information(self, "Save Successful", f"Successfully saved {self.packet_store.get_packet_count()} packets.")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save file:\n{str(e)}")

    def _extract_packet_info(self, packet):
        """Helper to safely extract strings for CSV/JSON."""
        summary = {
            "time": datetime.datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f'),
            "src": "N/A", "dst": "N/A", "proto": "Other",
            "len": len(packet), "info": packet.summary()
        }
        
        if IP in packet:
            summary["src"] = packet[IP].src
            summary["dst"] = packet[IP].dst
            summary["proto"] = "IP"
        elif ARP in packet:
            summary["src"] = packet[ARP].psrc
            summary["dst"] = packet[ARP].pdst
            summary["proto"] = "ARP"
            
        if packet.haslayer(http.HTTPRequest) or packet.haslayer(http.HTTPResponse): summary["proto"] = "HTTP"
        elif packet.haslayer(dns.DNS): summary["proto"] = "DNS"
        elif packet.haslayer(TCP): summary["proto"] = "TCP"
        elif packet.haslayer(UDP): summary["proto"] = "UDP"
        elif packet.haslayer(ICMP): summary["proto"] = "ICMP"
        
        return summary

    def export_to_csv(self):
        packets = self.packet_store.get_all_packets()
        if not packets:
            QMessageBox.warning(self, "Export Error", "No packets to export!")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Export to CSV", "", "CSV Files (*.csv)")
        if not file_path: return
        if not file_path.endswith('.csv'): file_path += '.csv'

        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for i, packet in enumerate(packets):
                    info = self._extract_packet_info(packet)
                    writer.writerow({
                        'No.': i + 1,
                        'Time': info['time'],
                        'Source': info['src'],
                        'Destination': info['dst'],
                        'Protocol': info['proto'],
                        'Length': info['len'],
                        'Info': info['info']
                    })
            self.statusBar().showMessage(f"Exported {len(packets)} rows to CSV", 3000)
            QMessageBox.information(self, "Export Successful", f"Successfully exported {len(packets)} packets to CSV format.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def export_to_json(self):
        packets = self.packet_store.get_all_packets()
        if not packets:
            QMessageBox.warning(self, "Export Error", "No packets to export!")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Export to JSON", "", "JSON Files (*.json)")
        if not file_path: return
        if not file_path.endswith('.json'): file_path += '.json'

        try:
            data = []
            for i, packet in enumerate(packets):
                info = self._extract_packet_info(packet)
                info['number'] = i + 1
                data.append(info)
            
            with open(file_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, indent=4)
                
            self.statusBar().showMessage(f"Exported {len(packets)} packets to JSON", 3000)
            QMessageBox.information(self, "Export Successful", f"Successfully exported {len(packets)} packets to JSON format.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def closeEvent(self, event):
        if self.capture_manager: self.capture_manager.cleanup()
        if self.geoip_manager: self.geoip_manager.close()
        # Clean up all workers
        if self.file_loader_thread and self.file_loader_thread.isRunning():
            self.file_loader_worker.stop()
            self.file_loader_thread.quit()
            self.file_loader_thread.wait(1000)
        if self.analysis_thread and self.analysis_thread.isRunning():
            self.analysis_worker.stop()
            self.analysis_thread.quit()
            self.analysis_thread.wait(1000)
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())