import socket
import socketserver
import threading
import unittest
from unittest.mock import patch
import scanner

class HTTP(socketserver.BaseRequestHandler):
    def handle(self):
        if not self.request.recv(4096):
            return
        self.request.sendall(b"HTTP/1.1 200 OK\r\nX-Content-Type-")
        self.request.sendall(b"Options: nosniff\r\n\r\n")

class ScannerTests(unittest.TestCase):
    def test_port_ranges(self):
        self.assertEqual(scanner.parse_ports("22,80,80,100-102"), [22, 80, 100, 101, 102])
        for invalid in ("", "0", "20-10", "65536", "1-2-3"):
            with self.assertRaises(Exception):
                scanner.parse_ports(invalid)

    def test_real_tcp_scan_and_http_probe(self):
        with socketserver.TCPServer(("127.0.0.1", 0), HTTP) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            try:
                with patch.object(scanner, "HTTP_PORTS", {port}):
                    report = scanner.scan("127.0.0.1", [port], timeout=2)
                self.assertEqual(report["open_ports"][0]["port"], port)
                self.assertEqual([f["finding"] for f in report["findings"]], ["Unencrypted HTTP available"])
            finally:
                server.shutdown()
                thread.join()

    def test_redis_and_memcached_auth_responses(self):
        with patch.object(scanner, "request_bytes", return_value=b"+PONG\r\n"):
            self.assertEqual(scanner.inspect("127.0.0.1", "localhost", 6379, 1)[0]["severity"], "high")
        with patch.object(scanner, "request_bytes", return_value=b"-NOAUTH Authentication required.\r\n"):
            self.assertEqual(scanner.inspect("127.0.0.1", "localhost", 6379, 1), [])
        with patch.object(scanner, "request_bytes", return_value=b"STAT pid 123\r\n"):
            self.assertEqual(scanner.inspect("127.0.0.1", "localhost", 11211, 1)[0]["severity"], "high")

    def test_tls_certificate_failure(self):
        import ssl
        error = ssl.SSLCertVerificationError(1, "verification failed")
        error.verify_message = "certificate has expired"
        with patch.object(scanner, "request_bytes", side_effect=error):
            self.assertIn("TLS certificate", scanner.inspect("127.0.0.1", "localhost", 443, 1)[0]["finding"])

if __name__ == "__main__":
    unittest.main()
