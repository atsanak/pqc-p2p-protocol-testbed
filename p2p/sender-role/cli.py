#!/usr/bin/env python3
"""p2p/sender-role/cli — mode-2 developer entry point (p2p-requirements.md's "Sender API").

Usage:
  cli.py message <receiver-name> <json-string> [--tech TECH]
  cli.py deliver <receiver-name> <local-file> [dest-filename] [--timeout S] [--tech TECH]
  cli.py put-file <receiver-name> <local-file> [dest-filename] [--job-id ID] [--mode 0755] [--timeout S] [--tech TECH]
  cli.py status  <receiver-name> [--tech TECH] [--details]
  cli.py self
  cli.py rm      <receiver-name> <command> [--timeout S] [--echo] [--tech TECH]
  cli.py ml      <receiver-name> <method> [json-params] [--timeout S] [--tech TECH]
  cli.py fetch   <receiver-name> <remote-path> [local-file] [--tech TECH]
  cli.py path    <receiver-name>

`rm` is DEVICE→DEVICE remote management (2026-07-28): the command runs ON THE RECEIVER, which
decides whether to run it from this sender's certificate and the Server's per-pair policy verdict —
the same two facts that gate a message. In-tenant and cross-tenant differ only in which policy
table is consulted. Exit status is the remote command's own.

`ml` is the ML use case (2026-07-29): ONE enumerated ML operation, run on the receiver by the
receiver's own device/gateway agent. It is what the Tenant-Admin GUI drives when it is impersonating
this node as a sender — the tenant admin coordinates, this sender acts. `<method>` is one of
receiver-role/handlers/ml.py's ML_METHODS (list_models · get_model · read_model_file · deliver_model
· run_model · start_run · stop_run · run_status · set_params · load_model · run_benchmark ·
start_inference · stop_inference) and `[json-params]` is the same params object the identical
ThingsBoard RPC takes. Exits 0 when the ML call itself succeeded.

`--timeout S` on deliver/put-file (2026-10-01, OPTIONAL) raises the sender's wait floor from the default 10 s to S seconds
(CoAP also adds P2P_COAP_PER_BLOCK_S, default 0.5 s, per 1 KiB block of the envelope; that env var is the other knob). Omit both and the
waits are unchanged. Use it for big blobs over a slow path: a 40 KB envelope is ~40 blocks = the 30 s budget.

`put-file` (2026-09-26) is `deliver` with rm_agent.put_file's contract: the bytes land in the
receiver's per-job folder, sha256-checked before the write, mode applied, idempotent. The reply's
`path` is what a follow-up `rm` runs.

`fetch` (2026-09-29, on-dev-api P4.1) is the PULL use case: read ONE file off the receiver, which
serves it only from under its own P2P_FETCH_ROOTS (receiver-role/handlers/fetch.py). The bytes are
sha256-checked on arrival and written to [local-file] (default: the remote basename, in the
current directory); when run under sudo the file is chowned back to the invoking user. The JSON
printed is the receiver's reply minus the bytes, plus `local_path`.

`path` sends nothing: it prints how this node reaches the receiver — the hop chain the Server
computes from the plan (the shared gateway, this tenant's Router-PC, or the cross-tenant WireGuard
hub), which is the path the data then takes.

TWO INDEPENDENT AXES (2026-07-28, operator-directed). The command is the USE CASE — what you are
exchanging; `--tech` is how it is protected. Every use case runs on every tech:

  --tech mtls       TLS 1.3 mutual auth (default). The peer certificate is the identity.
  --tech https      TLS 1.3, server-authenticated only, on the receiver's :P2P_HTTPS_PORT. No
                    client certificate; identity is an RSA-signed envelope in the body. Weaker
                    than mtls — see client.py's module docstring before choosing it.
  --tech pqc        mtls PLUS an ML-DSA-65-signed envelope. Requires a PQC identity minted and
                    provisioned on this node (PQC-bench/ca/pqc_ca.py); raises a clear error, not a
                    silent classical-only send, if missing.
  --tech coap-enc   CoAP/UDP, payload hybrid-encrypted to the receiver, ciphertext signed.
  --tech coap       CoAP/UDP with NO encryption (RFC 7252 NoSec) — the payload is cleartext on
                    the wire. Identity is unchanged: the same signed cert envelope and the same
                    per-pair policy check as coap-enc. Confidentiality is the only thing given
                    up, which is the point — a constrained node that cannot afford RSA-OAEP+
                    AES-GCM per message can still prove who it is.

Back-compatible spellings, unchanged in meaning: `--pqc` == `--tech pqc`, and the old
`cli.py message-coap <receiver> <json>` == `cli.py message <receiver> <json> --tech coap-enc`.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from client import TECHS, Client, tech_listing  # noqa: E402


# Flags that take a value, so both the flag AND the token after it must come out of the positional
# arguments. Kept as a table because getting this wrong is silent: a stray `30` left in the
# positionals becomes a filename or a command.
VALUE_FLAGS = ("--tech", "--timeout", "--job-id", "--mode")


def _split(argv):
    """-> (positionals, flags). One pass, so a flag's value can never be mistaken for a positional
    (the pre-2026-07-28 version filtered `--*` out and then guessed which trailing positional was
    `--tech`'s value by comparing it against the tech name — which worked only for --tech, and only
    because tech names never collide with filenames)."""
    positional, flags, i = [], {}, 0
    while i < len(argv):
        a = argv[i]
        if a in VALUE_FLAGS:
            if i + 1 >= len(argv):
                raise SystemExit(f"{a} needs a value")
            flags[a], i = argv[i + 1], i + 2
            continue
        if a.startswith("--"):
            flags[a], i = True, i + 1
            continue
        positional.append(a)
        i += 1
    return positional, flags


def _tech(flags):
    """The tech for this call, or None for the default. An unknown tech is refused here rather than
    at the far end of a connection. `--pqc` is the legacy spelling of `--tech pqc`."""
    if flags.get("--pqc"):
        return "pqc"
    tech = flags.get("--tech")
    if tech is None:
        return None
    if tech not in TECHS:
        raise SystemExit(f"unknown tech {tech!r} — one of: " + tech_listing())
    return tech


def main(argv):
    if len(argv) == 2 and argv[1] == "self":
        # 2026-10-02: THIS sender's own Network Map row, from its on-board API (no P2P traffic) —
        # the sender half of "details for the sender and its receivers" (`status --details`).
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))     # p2p/ root, for `common`
        from common import onboard
        result = onboard.map_details(max_age=0)
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd, receiver = argv[1], argv[2]
    rest = argv[3:]
    # `message-coap` was the CoAP transport's own command back when it was the only use case that
    # transport carried. It is now just `message --tech coap-enc`, kept working for existing scripts.
    if cmd == "message-coap":
        cmd, rest = "message", rest + ["--tech", "coap-enc"]
    try:
        positional, flags = _split(rest)
        tech = _tech(flags)
    except SystemExit as e:
        print(e)
        return 2

    c = Client()
    if cmd == "path":
        # Sends nothing — just the resolve every other command makes first.
        print(json.dumps(c.path(receiver), indent=2))
        return 0
    if cmd == "rm":
        if not positional:
            print(__doc__)
            return 2
        timeout = flags.get("--timeout")
        result = c.remote_exec(receiver, positional[0],
                               timeout=int(timeout) if timeout else None, tech=tech)
        if flags.get("--echo"):
            # Interactive use: the remote streams raw, on OUR matching streams, the way ssh does.
            # NOT the default, because everything that drives this CLI programmatically (the API's
            # TenantAPI._p2p_cli) reads stdout as one JSON object — and a remote command that
            # happens to print a brace would corrupt that parse. So the machine-readable form is
            # what you get unless you ask for the human one; the output is in the JSON either way.
            sys.stdout.write(result.get("stdout") or "")
            sys.stderr.write(result.get("stderr") or "")
        else:
            print(json.dumps(result, indent=2))
        # The REMOTE command's exit code is this process's exit code, so `cli.py rm` composes in a
        # shell the way ssh does. A refusal or a transport failure has no rc of its own -> 1.
        return result["rc"] if isinstance(result.get("rc"), int) else 1
    if cmd == "ml":
        if not positional:
            print(__doc__)
            return 2
        method = positional[0]
        try:
            params = json.loads(positional[1]) if len(positional) > 1 else {}
        except ValueError as e:
            print(f"params must be a JSON object: {e}")
            return 2
        timeout = flags.get("--timeout")
        result = c.ml_op(receiver, method, params,
                         timeout=int(timeout) if timeout else None, tech=tech)
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1
    if cmd == "fetch":
        if not positional:
            print(__doc__)
            return 2
        remote = positional[0]
        local_path = Path(positional[1] if len(positional) > 1 else Path(remote).name)
        result = c.fetch_file(receiver, remote, tech=tech)
        data = result.pop("data", None)
        if result.get("ok") and data is not None:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(data)
            uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
            if uid and gid and os.geteuid() == 0:
                try:
                    os.chown(local_path, int(uid), int(gid))
                except OSError:
                    pass
            result["local_path"] = str(local_path.resolve())
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok") else 1
    if cmd == "deliver":
        if not positional:
            print(__doc__)
            return 2
        local_path = Path(positional[0])
        dest = positional[1] if len(positional) > 1 else local_path.name
        tmo = flags.get("--timeout")
        result = c.deliver_file(receiver, local_path.read_bytes(), dest, tech=tech,
                                timeout=int(tmo) if tmo else None)
    elif cmd == "put-file":
        if not positional:
            print(__doc__)
            return 2
        local_path = Path(positional[0])
        dest = positional[1] if len(positional) > 1 else local_path.name
        tmo = flags.get("--timeout")
        result = c.put_file(receiver, local_path.read_bytes(), dest, job_id=flags.get("--job-id"),
                            mode=flags.get("--mode"), tech=tech, timeout=int(tmo) if tmo else None)
    elif cmd == "message":
        if not positional:
            print(__doc__)
            return 2
        result = c.send_message(receiver, json.loads(positional[0]), tech=tech)
    elif cmd == "status":
        result = c.get_status(receiver, tech=tech, details=bool(flags.get("--details")))
    else:
        print(__doc__)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
