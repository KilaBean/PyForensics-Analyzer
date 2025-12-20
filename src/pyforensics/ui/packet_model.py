from PySide6.QtCore import QAbstractTableModel, Qt, QModelIndex
from ..core.parser_engine import parse_packet_summary


class PacketModel(QAbstractTableModel):
    """
    Table model for displaying packets.
    Uses incremental row insertion to avoid Shiboken crashes.
    """
    def __init__(self, packet_store, parent=None):
        super().__init__(parent)
        self._packet_store = packet_store
        self._headers = [
            "No.", "Time", "Source",
            "Destination", "Protocol", "Length", "Info"
        ]

    def rowCount(self, parent=QModelIndex()):
        return self._packet_store.get_packet_count()

    def columnCount(self, parent=QModelIndex()):
        return len(self._headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if role == Qt.DisplayRole:
            packet = self._packet_store.get_packet(row)
            if not packet:
                return "N/A"

            summary = parse_packet_summary(packet)
            summary["No."] = row + 1   # ✅ FIX

            return str(summary.get(self._headers[col], "N/A"))

        if role == Qt.TextAlignmentRole:
            if col in (0, 5):
                return Qt.AlignRight | Qt.AlignVCenter

        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self._headers[section]
        return None

    # ------------------------------------------------------------------
    # SAFE incremental update (NO layoutChanged)
    # ------------------------------------------------------------------
    def packet_added(self):
        row = self.rowCount()
        self.beginInsertRows(QModelIndex(), row, row)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self.endResetModel()
