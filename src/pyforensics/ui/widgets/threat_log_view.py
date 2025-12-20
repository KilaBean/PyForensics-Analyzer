# src/pyforensics/ui/widgets/threat_log_view.py
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PySide6.QtGui import QColor, QBrush

class ThreatLogView(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["Time", "Severity", "Threat Type", "Source", "Details"])
        
        # Style
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        
        # Resize
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents) # Time
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents) # Severity
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents) # Type
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents) # Source
        header.setSectionResizeMode(4, QHeaderView.Stretch)          # Details

    def add_alert(self, alert):
        row = self.rowCount()
        self.insertRow(row)

        # Map fields
        items = [
            alert['timestamp'],
            alert['severity'],
            alert['title'],
            alert['src'],
            alert['details']
        ]

        # Determine Color based on Severity
        sev = alert['severity']
        color = QColor("#d32f2f") # High (Red)
        if sev == "Medium": color = QColor("#f57c00") # Orange
        if sev == "Low": color = QColor("#fbc02d") # Yellow

        for i, text in enumerate(items):
            item = QTableWidgetItem(str(text))
            # Color the text for Severity column
            if i == 1: 
                item.setForeground(QBrush(color))
                item.setToolTip(f"{sev} Priority Alert")
            self.setItem(row, i, item)
            
        self.scrollToBottom()