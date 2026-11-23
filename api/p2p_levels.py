"""The 21 P2P techs grouped by security level, one line each -- ONE dict shared by the Tenant-Admin
Desktop-GUI (panels/ml_fl.py `_LEVELS`, panels/protocol_picker.py) and TenantAPI (`protocol_rows`,
`p2p_levels`), so the two cannot drift. Stdlib only.

Levels follow what each handshake makes post-quantum -- the KEY EXCHANGE, the CERTIFICATES, or neither:
  Plaintext / Classical (X25519 + RSA) / PQ-KEX only (hybrid KEX, classical certs) / App-layer PQC
  (classical handshake, post-quantum part inside the signed payload) / Post-quantum (hybrid KEX AND ML-DSA-65 certs).
(2026-10-02: `coap-dtls-pqc*` use the fleet's CLASSICAL certificate, so they are PQ-KEX only; `coap-pqc` keeps the
classical RSA signature, so it is an envelope tech.)
2026-10-23 (owner: "PQC always means ML-KEM-768 and ML-DSA-65"): every `*pqc*` tech is now pure ML-KEM-768 key
exchange + ML-DSA-65 for every certificate and signature, so they all sit in the two Post-quantum levels; `pqc`
is mtls with every algorithm post-quantum (ML-KEM-768 + ML-DSA-65 certificates both sides, no envelope). pqkex* (hybrid KEX, ML-DSA
certs) stays where it was, as a level of its own.
"""
P2P_LEVELS = {
    "Plaintext": [("http", "HTTP :8442, no encryption"),
                  ("coap", "CoAP UDP :5683, no encryption")],
    "Classical": [("mtls", "TLS 1.3 mutual (default)"),
                  ("https", "TLS 1.3 server-auth"),
                  ("coap-enc", "CoAP, AES-256-GCM + RSA payload"),
                  ("coap-dtls", "CoAP over DTLS 1.3, X25519 + RSA certs"),
                  ("coap-dtls-mutual", "CoAP over DTLS 1.3, X25519 + RSA certs both sides"),
                  ("quic-classical", "HTTP/3 over QUIC, X25519 + RSA certs"),
                  ("quic-classical-mutual", "HTTP/3 over QUIC, X25519 + RSA certs both sides")],
    "PQ-KEX only (hybrid, classical certs)": [
        ("hybrid", "hybrid X25519MLKEM768 TLS 1.3, classical RSA cert"),
        ("hybrid-mutual", "hybrid TLS 1.3, classical RSA certs both sides"),
        ("quic-hybrid", "HTTP/3 over QUIC, hybrid KEX, classical RSA cert"),
        ("quic-hybrid-mutual", "HTTP/3 over QUIC, hybrid KEX, classical RSA certs both sides")],
    "Hybrid KEX + ML-DSA certs": [
        ("pqkex", "hybrid X25519MLKEM768 TLS 1.3, ML-DSA server cert"),
        ("pqkex-mutual", "hybrid TLS 1.3, ML-DSA both sides")],
    "Post-quantum (server auth)": [
        ("quic-pqc", "HTTP/3 over QUIC, ML-KEM-768 + ML-DSA-65 server cert, ML-DSA-65 signed sender"),
        ("coap-pqc", "CoAP, ML-KEM-768 key wrap + AES-GCM, ML-DSA-65 signatures both ways"),
        ("coap-dtls-pqc", "CoAP over DTLS 1.3, ML-KEM-768 + ML-DSA-65 server cert, ML-DSA-65 signatures")],
    "Post-quantum (mutual)": [
        ("pqc", "TLS 1.3, ML-KEM-768 + ML-DSA-65 certs both sides (no envelope)"),
        ("quic-pqc-mutual", "HTTP/3 over QUIC, ML-KEM-768 + ML-DSA-65 certs both sides"),
        ("coap-dtls-pqc-mutual", "CoAP over DTLS 1.3, ML-KEM-768 + ML-DSA-65 certs both sides")],
}
