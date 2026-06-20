"""
Nemesis Retest Tool — standalone entry point.

Development:  python run.py
Frozen .app:  double-click Nemesis.app  (built by PyInstaller)
"""
import multiprocessing
import os
import sys


def _setup_frozen_env():
    """
    When running as a PyInstaller onefile binary:
      - Change to the directory containing the executable so that relative
        paths for config/ and data/ point to a writable location next to it.
      - sys._MEIPASS holds the read-only bundled resources (frontend/, src/).
    """
    if not getattr(sys, "frozen", False):
        return

    exe_dir = os.path.dirname(sys.executable)
    os.chdir(exe_dir)

    for d in ["config", "data/logs", "data/assets"]:
        os.makedirs(d, exist_ok=True)


def main():
    _setup_frozen_env()

    import uvicorn
    from src.main import app  # noqa: imported here so PyInstaller can analyse it

    print()
    print("=" * 58)
    print("  Nemesis Retest Tool")
    print("  Open http://localhost:8000 in your browser")
    print("  Press Ctrl+C to stop")
    print("=" * 58)
    print()

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")


if __name__ == "__main__":
    multiprocessing.freeze_support()   # required for Windows frozen builds
    main()
