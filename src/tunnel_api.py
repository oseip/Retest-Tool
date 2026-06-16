"""REST endpoints for the local port-forwarding (tunnel) feature."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from . import port_forward

router = APIRouter(prefix="/api/tunnels")


class StartTunnelRequest(BaseModel):
    label: str
    target_host: str
    target_port: int
    local_port: int


@router.get("")
def get_tunnels():
    return port_forward.list_tunnels()


@router.post("")
def start_tunnel(req: StartTunnelRequest):
    from . import main as main_mod
    cfg = main_mod.cfg
    if cfg is None:
        raise HTTPException(400, "App is not configured yet.")

    # local_port == 0 means "pick any free port" — see port_forward.start_tunnel.
    if not (1 <= req.target_port <= 65535) or not (0 <= req.local_port <= 65535):
        raise HTTPException(400, "Ports must be between 1 and 65535 (local_port may be 0 for auto).")

    try:
        tunnel_id = port_forward.start_tunnel(
            cfg, req.label, req.target_host, req.target_port, req.local_port
        )
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))

    return {"id": tunnel_id}


@router.delete("/{tunnel_id}")
def delete_tunnel(tunnel_id: str):
    if not port_forward.remove_tunnel(tunnel_id):
        raise HTTPException(404, "Unknown tunnel")
    return {"ok": True}
