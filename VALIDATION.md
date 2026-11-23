# Validation

Five local checks and the GitHub Actions workflow passed: trusted HTTPS, rejected
unknown CA, rejected hostname mismatch, replacement on the same endpoint, and
future-time expiry verification.

## Coverage

Fresh disposable certificates and live loopback TLS connections. OpenSSL evaluates
expiry at a future verification time; the system clock stays unchanged. Certificate
replacement uses stop/start. ACME and public certificate issuance are separate integrations.
