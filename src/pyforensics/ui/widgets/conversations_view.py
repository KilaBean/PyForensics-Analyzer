from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import Qt

class ConversationsView(QTreeWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Endpoints", "Packets", "Bytes"])
        self.setAlternatingRowColors(True)
        self.setRootIsDecorated(False)
        
        # Ensure uniform row height for cleaner look
        self.uniformRowHeights = True

    def populate(self, conversations: list):
        self.clear()
        for conv in conversations:
            item = QTreeWidgetItem(self)
            item.setText(0, conv["Endpoints"])
            item.setText(1, str(conv["Packets"]))
            item.setText(2, str(conv["Bytes"]))
            
            # Right align numeric columns for modern dashboard feel
            item.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
            item.setTextAlignment(2, Qt.AlignRight | Qt.AlignVCenter)
            
            item.setData(0, Qt.UserRole, conv)