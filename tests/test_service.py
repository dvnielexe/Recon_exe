import errno
import socket
import unittest
from unittest.mock import patch


from recon.modules.services import scan_port, scan

class TestServices(unittest.TestCase):

    @patch("recon.modules.services.socket.socket")
    def test_open_port(self, mock_socket):

        mock_sock = mock_socket.return_value.__enter__.return_value
        mock_sock.connect_ex.return_value = 0

        result = scan_port("127.0.0.1", 8000)

        self.assertEqual(result["state"], "open")
        self.assertEqual(result["service"], "http")
        self.assertIsNone(result["version"])


    @patch("recon.modules.services.socket.socket")
    def test_closed_port(self, mock_socket):

        mock_sock = mock_socket.return_value.__enter__.return_value
        mock_sock.connect_ex.return_value = errno.ECONNREFUSED

        result = scan_port("127.0.0.1", 8000)

        self.assertEqual(result["state"], "closed")


    @patch("recon.modules.services.socket.socket")
    def test_unknown_port(self, mock_socket):

        mock_sock = mock_socket.return_value.__enter__.return_value
        mock_sock.connect_ex.return_value = errno.ETIMEDOUT

        result = scan_port("127.0.0.1", 9000)

        self.assertEqual(result["state"], "unknown")


    @patch("recon.modules.services.scan_port")
    def test_custom_port_list(self, mock_scan_port):

        mock_scan_port.side_effect = [
            {"port": 80},
            {"port": 443}
        ]

        results = scan("127.0.0.1", ports=[80, 443])

        self.assertEqual(len(results), 2)
        self.assertEqual(mock_scan_port.call_count, 2)


if __name__ == "__main__":
    unittest.main()
