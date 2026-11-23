"""Loopback-only TLS trust, identity, expiry and certificate replacement drills."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest


def openssl(*args, check=True):
    return subprocess.run(["openssl", *map(str, args)], check=check,
                          capture_output=True, text=True, timeout=30)


def issue_certificates(directory):
    """Issue disposable lab certificates, never install a trust root on the host."""
    ca_key, ca = directory / "ca.key", directory / "ca.pem"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-keyout", ca_key, "-out", ca, "-days", "7", "-subj", "/CN=Disposable Lab CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")
    extensions = directory / "server.ext"
    extensions.write_text("basicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,digitalSignature,keyEncipherment\n"
                          "extendedKeyUsage=serverAuth\n"
                          "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                          "subjectKeyIdentifier=hash\n"
                          "authorityKeyIdentifier=keyid,issuer\n")
    for name, serial, days in [("initial", "1001", "2"), ("replacement", "1002", "4")]:
        key, csr, cert = [directory / (name + suffix) for suffix in (".key", ".csr", ".pem")]
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-keyout", key, "-out", csr, "-subj", "/CN=localhost")
        openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
                "-set_serial", serial, "-days", days, "-sha256", "-extfile", extensions,
                "-out", cert)
        key.chmod(0o600)
    ca_key.chmod(0o600)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


@contextmanager
def serve(directory, identity="initial", port=0):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory / (identity + ".pem"), directory / (identity + ".key"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    try:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            worker.join(timeout=5)
            if worker.is_alive():
                raise RuntimeError("Lab server did not stop")
    finally:
        server.server_close()


def probe(port, context, hostname="localhost"):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as connection:
            certificate = connection.getpeercert()
            connection.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            chunks = []
            while True:
                part = connection.recv(4096)
                if not part:
                    break
                chunks.append(part)
            response = b"".join(chunks)
    if not response.startswith(b"HTTP/1.0 200") or not response.endswith(b"ok\n"):
        raise RuntimeError("Unexpected HTTPS response")
    return certificate["serialNumber"]


class CertificateLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="certificate-lab-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        issue_certificates(cls.directory)

    def trusted_context(self):
        return ssl.create_default_context(cafile=str(self.directory / "ca.pem"))

    def test_trusted_certificate_serves_https(self):
        with serve(self.directory) as port:
            self.assertEqual(probe(port, self.trusted_context()), "03E9")

    def test_untrusted_ca_is_rejected(self):
        # An empty trust store isolates this test from any host-installed roots.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with serve(self.directory) as port:
            with self.assertRaises(ssl.SSLCertVerificationError):
                probe(port, context)

    def test_wrong_hostname_is_rejected(self):
        with serve(self.directory) as port:
            with self.assertRaises(ssl.SSLCertVerificationError) as failure:
                probe(port, self.trusted_context(), hostname="wrong.example")
            self.assertIn("Hostname mismatch", str(failure.exception))

    def test_replacement_changes_identity_on_same_endpoint(self):
        with serve(self.directory) as port:
            original = probe(port, self.trusted_context())
        # This explicitly tests stop/start replacement, not a zero-downtime reload.
        with serve(self.directory, "replacement", port=port) as same_port:
            replacement = probe(same_port, self.trusted_context())
        self.assertEqual((original, replacement), ("03E9", "03EA"))

    def test_future_validation_rejects_expired_initial_certificate(self):
        future = str(int(time.time()) + 3 * 24 * 3600)
        common = ("verify", "-attime", future, "-purpose", "sslserver",
                  "-verify_hostname", "localhost", "-CAfile", self.directory / "ca.pem")
        expired = openssl(*common, self.directory / "initial.pem", check=False)
        self.assertNotEqual(expired.returncode, 0)
        self.assertIn("certificate has expired", expired.stdout + expired.stderr)
        openssl(*common, self.directory / "replacement.pem")


if __name__ == "__main__":
    unittest.main(verbosity=2)
