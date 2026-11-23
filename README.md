# Certificate lifecycle lab

A disposable loopback HTTPS lab for understanding certificate trust, hostname
validation, expiration, and replacement. No cloud account or public endpoint is needed.

## Run

Install Python 3.11 or later, OpenSSL 3, and Make, then run:

```sh
make test
```

The five checks create a temporary CA and two server certificates, start an HTTPS
listener on `127.0.0.1` using an available port, and verify:

- The trusted initial certificate serves a successful HTTPS response.
- A client with no trusted CA rejects the connection.
- A trusted client rejects an incorrect hostname.
- Stop/start certificate replacement changes the identity on the same port.
- OpenSSL verification three days ahead rejects the initial certificate while
  accepting its longer-lived replacement.

Temporary keys and certificates are deleted when the test process exits normally,
including after test failures. The lab never installs a system trust root. A forced
process termination may leave the private temporary directory for manual removal.

See [validation](VALIDATION.md) for evidence and limits, and the
[replacement runbook](RUNBOOK.md) for an operational walkthrough.

This learning lab covers local trust and stop/start replacement. ACME, certificate
authority operations, revocation, and uninterrupted reload are separate integration exercises.

## References

- [Python TLS client verification](https://docs.python.org/3/library/ssl.html)
- [OpenSSL certificate requests](https://docs.openssl.org/3.5/man1/openssl-req/)
- [OpenSSL verification](https://docs.openssl.org/3.5/man1/openssl-verification-options/)
