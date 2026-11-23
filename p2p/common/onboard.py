"""p2p/common/onboard — ask THIS box's own on-board API (DeviceAPI / GatewayAPI) about itself.

Used by the receiver's `status` use case when the sender asks for `details` (receiver-role/handlers/
status.py), and by the sender CLI's `self` command (sender-role/cli.py) — so a P2P peer and the sender
report the SAME Network Map row (`map_details_self()`: ip, real_ip, role, lifecycle state, segment,
parent, hops, via_chain) that the Tenant-Admin GUI's Network Map shows, from one implementation.

Best effort and never raises: a box without the on-board API, or with an older one that has no
`map_details_self`, answers {"ok": False, "detail": ...}. The answer is cached for CACHE_TTL_S so a
burst of status calls costs one `/resolve` + one lifecycle read.
"""
import importlib
import os
import sys
import threading
import time

# Where the role installs put the on-board API (on-dev-api/deploy/service-install.sh uses the same).
CANDIDATES = (("/opt/testbed-role/API", "device_api", "DeviceAPI"),
              ("/opt/Gateway-PC/Gateway/python/API", "gateway_api", "GatewayAPI"))
CACHE_TTL_S = 15.0

_lock = threading.Lock()
_cache = {"at": 0.0, "value": None}
_api = {"obj": None, "tried": False, "detail": None}


def _load():
    """The on-board API object of this box, or None (with the reason in _api['detail'])."""
    if _api["tried"]:
        return _api["obj"]
    _api["tried"] = True
    for path, module, cls in CANDIDATES:
        if not os.path.isfile(os.path.join(path, module + ".py")):
            continue
        try:
            if path not in sys.path:
                sys.path.insert(0, path)
            _api["obj"] = getattr(importlib.import_module(module), cls)()
            return _api["obj"]
        except Exception as e:                       # noqa: BLE001 - reported, never raised
            _api["detail"] = f"{module} at {path} failed to load: {type(e).__name__}: {e}"
            return None
    _api["detail"] = "no on-board API on this box (looked in " + ", ".join(p for p, _, _ in CANDIDATES) + ")"
    return None


def map_details(max_age=CACHE_TTL_S):
    """This box's Network Map row -> the on-board API's map_details_self() answer, or
    {"ok": False, "detail"}. Cached for `max_age` seconds (0 = always fresh)."""
    with _lock:
        now = time.time()
        if _cache["value"] is not None and now - _cache["at"] < max_age:
            return dict(_cache["value"], cached_age_s=round(now - _cache["at"], 1))
        api = _load()
        if api is None:
            value = {"ok": False, "detail": _api["detail"]}
        elif not hasattr(api, "map_details_self"):
            value = {"ok": False, "detail": "this box's on-board API predates map_details_self (update it)"}
        else:
            try:
                value = api.map_details_self()
            except Exception as e:                   # noqa: BLE001 - reported, never raised
                value = {"ok": False, "detail": f"map_details_self failed: {type(e).__name__}: {e}"}
        _cache.update(at=now, value=value)
        return dict(value)
