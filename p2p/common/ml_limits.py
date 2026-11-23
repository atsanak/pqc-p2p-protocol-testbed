"""p2p/common/ml_limits — the one place the ML use case's time budget is written.

Same reasoning as `rm_limits.py`, and kept separate from it because the numbers legitimately differ:
an ML operation is a model delivery or a run, not a shell command, and its ordinary case is slower.
Both halves need these and they must agree — the RECEIVER caps how long it waits on its local ML
agent (receiver-role/handlers/ml.py), and the SENDER must wait at least that long plus a margin
before calling the peer unreachable (sender-role/client.py::_socket_timeout). Drift here is silent:
a sender that gives up first reports `PeerUnreachable` for an operation that then completes anyway,
leaving the receiver's ml.log and the comm-log mirror disagreeing about what happened.
"""

DEFAULT_TIMEOUT = 60        # seconds, when the sender names none
MAX_TIMEOUT = 300           # ceiling: a peer may not pin the receiver's ML agent open indefinitely
