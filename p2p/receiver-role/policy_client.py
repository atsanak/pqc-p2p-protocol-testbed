"""p2p/receiver-role/policy_client — asks the Server whether this pair is allowed (p2p-plan..md §3.1
layout comment: "asks the Tenant-Admin/Server whether this pair is allowed").

A thin wrapper over common/identity.py's authorize(), kept as its own module because Stage C's GUI
will call the exact same underlying /p2p-authorize join for its "effective state" display — this is
the one place receiver-role code asks the question, so it's the one place to change if that ever
needs caching or a different transport.
"""
from common import identity


def check(server_api_base, bootstrap_secret, sender, receiver, use_case=None):
    """-> (allowed: bool, reason: str). Raises nothing — an unreachable Server means "can't confirm
    allow", which this treats as a hard deny (fail closed, not fail open)."""
    try:
        return identity.authorize(server_api_base, bootstrap_secret, sender, receiver,
                                  use_case=use_case)
    except Exception as e:
        return False, f"policy check failed (fail-closed): {e}"
