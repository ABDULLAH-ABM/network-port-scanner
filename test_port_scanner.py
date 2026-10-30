import socket
import unittest
import port_scanner as ps


class ScannerTests(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(ps.parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])

    def test_parse_invalid(self):
        for bad in ("0", "70000", "10-5", "abc", ""):
            with self.assertRaises(ValueError):
                ps.parse_ports(bad)

    def test_detects_open_port(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        try:
            self.assertIn(port, ps.scan("127.0.0.1", [port]))
        finally:
            server.close()

    def test_closed_port(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.close()
        self.assertNotIn(port, ps.scan("127.0.0.1", [port]))


if __name__ == "__main__":
    unittest.main()
