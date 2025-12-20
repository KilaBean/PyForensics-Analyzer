# src/pyforensics/ui/theme.py

# --- PROTOCOL COLORS ---
# These must be defined here so the MainWindow can import them.
PROTOCOL_COLORS = {
    'HTTP': '#2E5C55',   # Dark Greenish
    'DNS':  "#54549E",   # Dark Lavender
    'TCP':  '#2D3047',   # Dark Purple/Blue
    'UDP':  "#003772",   # Dark Blue
    'ICMP': '#4A3B3E',   # Dark Pink/Red
    'ARP':  '#4D4835',   # Dark Tan
    'IP':   '#1E1E1E',   # Default Dark
    'Other':'#121212'    # Black
}

# A modern Dark Theme inspired by VS Code and Cyberpunk UIs
STYLESHEET = """
/* --- Global Base --- */
QWidget {
    background-color: #1e1e1e;
    color: #e0e0e0;
    font-family: "Segoe UI", "Roboto", "Helvetica", sans-serif;
    font-size: 9pt;
    border: none;
}

QMainWindow {
    background-color: #121212;
}

/* --- ScrollBars --- */
QScrollBar:vertical {
    border: none;
    background: #1e1e1e;
    width: 10px;
    margin: 0px;
}
QScrollBar::handle:vertical {
    background: #3a3a3a;
    min-height: 20px;
    border-radius: 5px;
}
QScrollBar::handle:vertical:hover {
    background: #4a4a4a;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    border: none;
    background: #1e1e1e;
    height: 10px;
    margin: 0px;
}
QScrollBar::handle:horizontal {
    background: #3a3a3a;
    min-width: 20px;
    border-radius: 5px;
}

/* --- Buttons --- */
QPushButton {
    background-color: #007acc;
    color: white;
    border-radius: 4px;
    padding: 6px 12px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #0098ff;
}
QPushButton:pressed {
    background-color: #005a9e;
}
QPushButton:disabled {
    background-color: #3a3a3a;
    color: #777;
}

/* --- Inputs --- */
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {
    background-color: #252526;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    padding: 4px;
    selection-background-color: #007acc;
}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {
    border: 1px solid #007acc;
}

/* --- Toolbar --- */
QToolBar {
    background-color: #252526;
    border-bottom: 1px solid #3e3e42;
    spacing: 5px;
    padding: 4px;
}

/* --- Menu Bar --- */
QMenuBar {
    background-color: #252526;
    border-bottom: 1px solid #3e3e42;
}
QMenuBar::item {
    padding: 5px 10px;
    background-color: transparent;
}
QMenuBar::item:selected {
    background-color: #3e3e42;
}
QMenu {
    background-color: #252526;
    border: 1px solid #454545;
}
QMenu::item {
    padding: 6px 20px;
}
QMenu::item:selected {
    background-color: #007acc;
}

/* --- Tables & TreeViews --- */
QTableView, QTreeWidget {
    background-color: #1e1e1e;
    border: none;
    selection-background-color: #264f78;
    alternate-background-color: #252526;
    selection-color: white;
}
QTableView::item, QTreeWidget::item {
    padding: 4px;
    border-bottom: 1px solid #2d2d2d;
}
QHeaderView::section {
    background-color: #2d2d2d;
    color: #cccccc;
    padding: 5px;
    border: none;
    border-right: 1px solid #3e3e42;
    border-bottom: 1px solid #3e3e42;
    font-weight: bold;
}

/* --- Dock Widgets --- */
QDockWidget {
    color: #e0e0e0;
    titlebar-close-icon: url(close.png); /* Fallback */
    titlebar-normal-icon: url(undock.png); /* Fallback */
}
QDockWidget::title {
    background-color: #252526;
    padding: 5px;
    text-align: center;
    border-bottom: 1px solid #3e3e42;
    font-weight: bold;
}

/* --- Status Bar --- */
QStatusBar {
    background-color: #007acc;
    color: white;
}
QLabel {
    background-color: transparent;
}
"""