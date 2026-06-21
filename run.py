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


def _free_port(port: int) -> None:
    """
    If the target port is still held by a previous process (e.g. a run that
    was stopped with Ctrl+C but whose socket lingered), kill that process so
    this run can bind cleanly.

    Best-effort — any exception is silently ignored so startup is never
    blocked by cleanup logic.
    """
    import errno
    import signal
    import socket
    import subprocess
    import time

    # 1. Quick probe — is the port actually in use?
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("", port))
            return  # port is free, nothing to do
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE:
                return  # some other socket error — let uvicorn handle it

    # 2. Port is busy — find the holder and terminate it
    print(f"  Port {port} still held by a previous run — releasing it…")
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL
            )
            pids: set[int] = set()
            for line in out.splitlines():
                parts = line.split()
                if (
                    len(parts) >= 5
                    and f":{port}" in parts[1]
                    and parts[3] == "LISTENING"
                ):
                    try:
                        pids.add(int(parts[4]))
                    except ValueError:
                        pass
            for pid in pids:
                if pid != os.getpid():
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        stderr=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                    )
        else:
            # macOS / Linux
            out = subprocess.check_output(
                ["lsof", "-ti", f":{port}"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for pid_str in out.strip().splitlines():
                try:
                    pid = int(pid_str.strip())
                except ValueError:
                    continue
                if pid != os.getpid():
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass

        # Give the OS a moment to fully release the socket
        time.sleep(0.8)

    except Exception:
        pass  # best-effort — if it fails, uvicorn will give its normal error


def main():
    _setup_frozen_env()
    _free_port(8000)

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
