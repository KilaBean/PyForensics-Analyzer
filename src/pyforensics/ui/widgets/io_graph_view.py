import pyqtgraph as pg
from PySide6.QtWidgets import QWidget, QVBoxLayout

class IOGraphView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        # Configure Plot Widget
        self.plot_widget = pg.PlotWidget(title="I/O Graph")
        self.plot_widget.setBackground('#1e1e1e') # Match theme background
        self.plot_widget.setLabel('left', 'Packets', color='#e0e0e0')
        self.plot_widget.setLabel('bottom', 'Time (s)', color='#e0e0e0')
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        
        # Style the axes
        self.plot_widget.getAxis('left').setPen('#e0e0e0')
        self.plot_widget.getAxis('bottom').setPen('#e0e0e0')
        self.plot_widget.getAxis('left').setTextPen('#e0e0e0')
        self.plot_widget.getAxis('bottom').setTextPen('#e0e0e0')
        
        self.layout.addWidget(self.plot_widget)
        
        # Create a curve with a modern neon color (Cyan/Green)
        self.plot_curve = self.plot_widget.plot(pen=pg.mkPen(color='#00ffcc', width=2))

    def update_plot(self, timestamps, packet_counts):
        if timestamps and packet_counts:
            self.plot_curve.setData(timestamps, packet_counts)