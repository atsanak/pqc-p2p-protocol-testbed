"""p2p/common/errors — the peer service's own exception types.

Kept separate from HTTP status codes: transports/http.py maps these to wire codes, but the
exceptions themselves are transport-agnostic so transports/coap.py (Stage D) can reuse them.
"""


class P2PError(Exception):
    """Base class for everything the peer service raises on purpose (as opposed to bugs)."""


class ResolveError(P2PError):
    """The Server's GET /resolve could not answer for a name (unknown node, or the Server itself
    is unreachable) — p2p-plan..md §2, Stage A calls this directly, no stand-in."""


class AuthorizationDenied(P2PError):
    """The §4.3 authorize() join said no. Carries the reason string from /p2p-authorize so the
    caller can show *why*, not just that it failed (p2p-plan..md §4.2's "log the reason precisely")."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class IdentityError(P2PError):
    """A cert problem: missing, expired, wrong CN, or doesn't chain to the CA — §3.2's "you cannot
    claim to be X without its cert.\""""


class PeerUnreachable(P2PError):
    """Connect/handshake failed. Stage A's deliberate liveness design (§7 Q7): this is how the
    caller finds out a path is down, not a pre-check against /resolve's realized block."""
