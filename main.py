import sys
import os
import traceback

# Add 'src' to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

try:
    from PySide6.QtWidgets import QApplication, QMessageBox
    print("✅ PySide6 imported successfully.")
except ImportError as e:
    print(f"❌ CRITICAL ERROR: PySide6 not found. Run 'pip install PySide6'.\nDetails: {e}")
    sys.exit(1)

def main():
    try:
        print("🚀 Starting Application...")
        app = QApplication(sys.argv)
        
        # Wrap the import of MainWindow to catch syntax/import errors inside it
        print("📦 Importing MainWindow...")
        from pyforensics.ui.main_window import MainWindow
        
        print("🖥️  Initializing Window...")
        window = MainWindow()
        window.show()
        
        print("✅ App Running.")
        sys.exit(app.exec())
        
    except Exception:
        # This catches ANY crash during launch and prints it clearly
        print("\n" + "="*60)
        print("❌ APPLICATION CRASHED")
        print("="*60)
        traceback.print_exc()
        print("="*60)
        input("\nPress Enter to close...") # Keeps terminal open

if __name__ == "__main__":
    main()