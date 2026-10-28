# Test fixtures

`test-only-idp-signing-key.pem` is an RSA key generated for the login flow test. It signs ID
tokens for the fake identity provider that `tests/login_flow.rs` runs on a local port, and
nothing else. It is not, and must never become, a key for anything real.
