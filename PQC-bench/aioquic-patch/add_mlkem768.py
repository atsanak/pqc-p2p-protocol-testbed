#!/usr/bin/env python3
"""Add the PURE ML-KEM-768 TLS group (codepoint 0x0201, FIPS 203, no X25519 half) to an aioquic tls.py that
already carries tls.py.patch (the X25519MLKEM768 hybrid + ML-DSA-65). 2026-10-23, owner's rule: "PQC always
means ML-KEM-768 and ML-DSA-65" -- the `quic-pqc*` techs now negotiate MLKEM768, not the hybrid.

Idempotent: a tls.py that already has the group is left untouched. The result is the same as applying the
current tls.py.patch to a stock aioquic 1.3.0 tls.py.

    usage: add_mlkem768.py [PATH_TO_aioquic/tls.py]   (default: the quic-pqc venv's)
"""
import sys

DEFAULT = "/opt/pqc-libs/quic-pqc-venv/lib/python3.13/site-packages/aioquic/tls.py"

EDITS = [
    # the group codepoint
    ("    X25519MLKEM768 = 0x11EC\n",
     "    X25519MLKEM768 = 0x11EC\n"
     "    # quic-pqc (2026-10-23): the PURE ML-KEM-768 group (codepoint 0x0201) -- key_share is the bare ML-KEM\n"
     "    # encapsulation key (client) / ciphertext (server), the shared secret is ML-KEM's alone.\n"
     "    MLKEM768 = 0x0201\n"),
    # client: its ephemeral key between ClientHello and ServerHello
    ("        self._hybrid_mlkem_private_key: Optional[mlkem.MLKEM768PrivateKey] = None\n",
     "        self._hybrid_mlkem_private_key: Optional[mlkem.MLKEM768PrivateKey] = None\n"
     "        self._mlkem_private_key: Optional[mlkem.MLKEM768PrivateKey] = None\n"),
    # client: offer it
    ("                key_share.append((Group.X25519MLKEM768, x25519_pub + mlkem_pub))\n"
     "                supported_groups.append(Group.X25519MLKEM768)\n",
     "                key_share.append((Group.X25519MLKEM768, x25519_pub + mlkem_pub))\n"
     "                supported_groups.append(Group.X25519MLKEM768)\n"
     "            elif group == Group.MLKEM768:\n"
     "                self._mlkem_private_key = mlkem.MLKEM768PrivateKey.generate()\n"
     "                key_share.append((Group.MLKEM768, self._mlkem_private_key.public_key().public_bytes(\n"
     "                    Encoding.Raw, PublicFormat.Raw)))\n"
     "                supported_groups.append(Group.MLKEM768)\n"),
    # client: decapsulate the server's ciphertext
    ("        shared_key: Optional[bytes] = None\n"
     "        if peer_hello.key_share[0] == Group.X25519MLKEM768:\n",
     "        shared_key: Optional[bytes] = None\n"
     "        if peer_hello.key_share[0] == Group.MLKEM768:\n"
     "            assert self._mlkem_private_key is not None\n"
     "            shared_key = self._mlkem_private_key.decapsulate(peer_hello.key_share[1])\n"
     "            self._mlkem_private_key = None\n"
     "            peer_public_key = None\n"
     "        elif peer_hello.key_share[0] == Group.X25519MLKEM768:\n"),
    # server: encapsulate to the client's key
    ("            if key_share[0] == Group.X25519MLKEM768:\n"
     "                peer_x25519_pub = x25519.X25519PublicKey.from_public_bytes(key_share[1][:32])\n",
     "            if key_share[0] == Group.MLKEM768:\n"
     "                peer_mlkem_pub = mlkem.MLKEM768PublicKey.from_public_bytes(key_share[1])\n"
     "                shared_key, mlkem_ct = peer_mlkem_pub.encapsulate()\n"
     "                hybrid_key_share = (Group.MLKEM768, mlkem_ct)\n"
     "                break\n"
     "            if key_share[0] == Group.X25519MLKEM768:\n"
     "                peer_x25519_pub = x25519.X25519PublicKey.from_public_bytes(key_share[1][:32])\n"),
]


def main(path):
    s = open(path).read()
    if "MLKEM768 = 0x0201" in s:
        print(f"{path}: already has MLKEM768, unchanged")
        return 0
    for old, new in EDITS:
        if s.count(old) != 1:
            print(f"{path}: anchor not found exactly once (is tls.py.patch applied?):\n{old}", file=sys.stderr)
            return 1
        s = s.replace(old, new)
    compile(s, path, "exec")
    open(path, "w").write(s)
    print(f"{path}: MLKEM768 added")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT))
