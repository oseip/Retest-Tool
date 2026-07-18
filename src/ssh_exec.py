import logging
import time
from typing import Callable, Optional, Tuple

import paramiko

from .config import JumpServerConfig, ClientConfig

log = logging.getLogger(__name__)


class KaliConnection:
    """
    Double-hop SSH connection: local → jump server → client Kali machine.
    Uses password authentication only (no keys).
    """

    def __init__(self, jump: JumpServerConfig, client: ClientConfig):
        self._jump_cfg = jump
        self._client_cfg = client
        self._jump: Optional[paramiko.SSHClient] = None
        self._kali: Optional[paramiko.SSHClient] = None

    def connect(self):
        log.info("Connecting to jump server %s:%d as %s", self._jump_cfg.host, self._jump_cfg.port, self._jump_cfg.user)
        self._jump = paramiko.SSHClient()
        self._jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._jump.connect(
            hostname=self._jump_cfg.host,
            port=self._jump_cfg.port,
            username=self._jump_cfg.user,
            password=self._jump_cfg.password,
            timeout=30,
            look_for_keys=False,
            allow_agent=False,
        )

        log.info("Opening channel to Kali via jump (localhost:%d)", self._client_cfg.kali_port)
        transport = self._jump.get_transport()
        channel = transport.open_channel(
            "direct-tcpip",
            dest_addr=("localhost", self._client_cfg.kali_port),
            src_addr=("127.0.0.1", 0),
        )

        self._kali = paramiko.SSHClient()
        self._kali.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self._kali.connect(
                hostname="localhost",
                username=self._client_cfg.kali_user,
                password=self._client_cfg.kali_password,
                sock=channel,
                timeout=30,
                look_for_keys=False,
                allow_agent=False,
            )
        except Exception:
            # The Kali hop failed (bad creds, host down, timeout). Tear down the
            # jump SSH session we already opened so it doesn't leak a live
            # session on the shared jump server for every failed attempt.
            self.close()
            raise
        log.info("Kali connection ready for client '%s'", self._client_cfg.label)

    def is_alive(self) -> bool:
        """True only if both hops' transports are open and active."""
        try:
            for client in (self._jump, self._kali):
                if client is None:
                    return False
                transport = client.get_transport()
                if transport is None or not transport.is_active():
                    return False
            return True
        except Exception:
            return False

    def exec_stream(self, command: str, on_line: Callable[[str], None],
                    timeout: int = 600, stop_event=None) -> int:
        """
        Execute command on Kali, streaming each output line to on_line().
        Uses a PTY so nmap doesn't buffer its output.
        Returns the exit code, or -9 if cancelled via stop_event.
        """
        # timeout=30 prevents indefinite blocking when the previous PTY session's
        # cleanup is still in progress on the server side.
        session = self._kali.get_transport().open_session(timeout=30)
        session.get_pty(term="xterm", width=200, height=50)
        session.exec_command(command)

        buf = b""
        deadline = time.time() + timeout
        exit_code = -1
        cancelled = False

        try:
            while True:
                if stop_event and stop_event.is_set():
                    cancelled = True
                    break
                if time.time() > deadline:
                    on_line(f"[ERROR] Command timed out after {timeout}s")
                    break
                if session.recv_ready():
                    chunk = session.recv(4096)
                    if not chunk:
                        # Empty recv means the channel was closed under us (e.g. disconnect)
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line_b, buf = buf.split(b"\n", 1)
                        line = line_b.decode("utf-8", errors="replace").rstrip("\r")
                        if line:
                            on_line(line)
                if session.exit_status_ready() and not session.recv_ready():
                    if buf.strip():
                        on_line(buf.decode("utf-8", errors="replace").strip())
                    # Capture exit code here, before close()
                    exit_code = session.recv_exit_status()
                    break
                # Detect SSH disconnect so we don't spin until the 600s deadline
                transport = self._kali.get_transport()
                if transport is None or not transport.is_active():
                    on_line("[ERROR] SSH connection lost")
                    break
                time.sleep(0.05)
        finally:
            try:
                session.close()
            except Exception:
                pass

        return -9 if cancelled else exit_code

    def exec(self, command: str, timeout: int = 60, stop_event=None) -> Tuple[str, str, int]:
        """Execute command on Kali, return (stdout, stderr, exit_code).
        Polls both stdout and stderr to avoid buffer deadlocks on double-hop channels."""
        chan = self._kali.get_transport().open_session(timeout=30)
        chan.exec_command(command)

        stdout_buf = b""
        stderr_buf = b""
        deadline = time.time() + timeout
        exit_code = -1

        try:
            while True:
                if stop_event and stop_event.is_set():
                    break
                if time.time() > deadline:
                    break
                if chan.recv_ready():
                    stdout_buf += chan.recv(65536)
                if chan.recv_stderr_ready():
                    stderr_buf += chan.recv_stderr(65536)
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    # In double-hop SSH the exit status can arrive before all bytes
                    # have propagated through the jump-server channel — especially
                    # for large responses (Nessus scan detail can be 1MB+).
                    # Drain until no new bytes arrive for 3 seconds; this covers
                    # slow real-world double-hop connections where bursts can be
                    # seconds apart even after the remote command has exited.
                    last_recv = time.time()
                    while time.time() - last_recv < 3.0 and time.time() < deadline:
                        got_data = False
                        if chan.recv_ready():
                            chunk = chan.recv(65536)
                            if chunk:
                                stdout_buf += chunk
                                got_data = True
                                last_recv = time.time()
                        if chan.recv_stderr_ready():
                            chunk = chan.recv_stderr(65536)
                            if chunk:
                                stderr_buf += chunk
                                got_data = True
                                last_recv = time.time()
                        if not got_data:
                            time.sleep(0.02)
                    exit_code = chan.recv_exit_status()
                    break
                time.sleep(0.05)
        finally:
            try:
                chan.close()
            except Exception:
                pass

        return (
            stdout_buf.decode("utf-8", errors="replace"),
            stderr_buf.decode("utf-8", errors="replace"),
            exit_code,
        )

    def close(self):
        for client in (self._kali, self._jump):
            if client:
                try:
                    client.close()
                except Exception:
                    pass

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()
