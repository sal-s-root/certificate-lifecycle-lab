# Validation

Local execution on November 23, 2026: all five checks passed.
Environment: Python 3.14.10; OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 29 Sep 2026).
Hosted workflow verification is checked after publication.
The checks use fresh disposable credentials and live loopback TLS handshakes.
Expiry is evaluated with OpenSSL's future-time verification, without changing the
system clock. This is not a client connection made with an already expired leaf.
No external service, cloud deployment, ACME renewal, or production reload is tested.
