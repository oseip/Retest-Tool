"""Interactive shell over WebSocket — a real PTY bash session on a client's
Kali box, streamed straight into an xterm.js terminal in the browser.

Opens its own dedicated double-hop SSH connection per session (independent
of the connections.py pool used by scans), so it works without first
clicking Connect in the SSH panel, and a long-running terminal session
(e.g. vim, top) never ties up the connection scans rely on.
"""
import asyncio
import json
import logging
import threading
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .ssh_exec import KaliConnection

log = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws/shell/{label}")
async def shell_websocket(websocket: WebSocket, label: str):
    from . import main as main_mod
    cfg = main_mod.cfg

    await websocket.accept()

    async def send(payload: dict):
        try:
            await websocket.send_text(json.dumps(payload))
        except Exception:
            pass

    if cfg is None:
        await send({"type": "error", "data": "App is not configured yet."})
        await websocket.close()
        return

    client_cfg = next((c for c in cfg.clients if c.label == label), None)
    if not client_cfg:
        await send({"type": "error", "data": f"Unknown client: {label}"})
        await websocket.close()
        return

    conn = KaliConnection(cfg.jump_server, client_cfg)
    loop = asyncio.get_event_loop()
    try:
        await send({"type": "output", "data": f"Connecting to {label}…\r\n"})
        await loop.run_in_executor(None, conn.connect)
    except Exception as exc:
        await send({"type": "error", "data": f"Could not connect: {exc}"})
        await websocket.close()
        return

    try:
        channel = conn._kali.get_transport().open_session(timeout=30)
        channel.get_pty(term="xterm-256color", width=80, height=24)
        channel.invoke_shell()
    except Exception as exc:
        await send({"type": "error", "data": f"Could not start shell: {exc}"})
        conn.close()
        await websocket.close()
        return

    log.info("Interactive shell opened for client '%s'", label)
    closed = threading.Event()

    def reader():
        try:
            while not closed.is_set():
                if channel.recv_ready():
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    text = chunk.decode("utf-8", errors="replace")
                    asyncio.run_coroutine_threadsafe(send({"type": "output", "data": text}), loop)
                elif channel.exit_status_ready():
                    break
                else:
                    time.sleep(0.02)
        except Exception as exc:
            asyncio.run_coroutine_threadsafe(
                send({"type": "error", "data": f"Shell read error: {exc}"}), loop
            )
        finally:
            asyncio.run_coroutine_threadsafe(send({"type": "closed"}), loop)

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()

    try:
        while True:
            msg = await websocket.receive_text()
            try:
                payload = json.loads(msg)
            except ValueError:
                continue
            kind = payload.get("type")
            if kind == "input":
                channel.send(payload.get("data", ""))
            elif kind == "resize":
                try:
                    channel.resize_pty(
                        width=int(payload.get("cols", 80)),
                        height=int(payload.get("rows", 24)),
                    )
                except Exception:
                    pass
    except WebSocketDisconnect:
        pass
    finally:
        closed.set()
        try:
            channel.close()
        except Exception:
            pass
        conn.close()
        log.info("Interactive shell closed for client '%s'", label)
