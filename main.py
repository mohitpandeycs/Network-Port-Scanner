import sys

from src.ui import ScannerGUI


def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-10), 7)
        except Exception:
            pass

    app = ScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
