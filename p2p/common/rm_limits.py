"""p2p/common/rm_limits — the one place the device→device RM use case's time budget is written.

Both halves need these numbers and they must agree: the RECEIVER caps how long a peer may keep a
command running (handlers/rm.py), and the SENDER has to wait at least that long plus a margin
before deciding the peer is unreachable (sender-role/client.py::_socket_timeout). Kept in `common/`
rather than duplicated because the failure mode of drift is silent and confusing — a sender that
gives up at 10s on a command the receiver happily runs for 30 reports `PeerUnreachable` for an
exchange that actually succeeded, and the receiver's own rm.log would show the command completing.
"""

DEFAULT_TIMEOUT = 30        # seconds, when the sender names none
MAX_TIMEOUT = 300           # ceiling: a peer may not pin the receiver open indefinitely
