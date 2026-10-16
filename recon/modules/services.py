import errno
import socket

DEFAULT_PORTS = [
    22,
    80,
    443,
    3306,
    5432,
    8000,
    8080
]

KNOWN_SERVICES = {
    22: "ssh",
    80: "http",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    8000: "http",
    8080: "http"
}

def scan_port(host, port, timeout=1.0):
    """Check the connection state of one port"""

    result = {
        "host": host,
        "port": port,
        "protocol": "tcp",
        "state": "unknown",
        "service": None,
        "version": None,
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            connection_result = sock.connect_ex((host, port))

        if connection_result == 0:
            result["state"] = "open"
            result["service"] = KNOWN_SERVICES.get(
                port, "unknown"
            )

        elif connection_result == errno.ECONNREFUSED: 
            result["state"] = "closed"

        elif connection_result == errno.ETIMEDOUT:
            result["state"] = "unknown"

        else:
            result["state"] = "unknown"

    except socket.timeout:
        result["state"] = "unknown"

    except OSError:
        result["state"] = "unknown"

    return result


def scan(host, ports=None, timeout=1.0):
    """Scan a selected list of TCP ports on an authorized host"""

    if ports is None:
        ports = DEFAULT_PORTS

    results = []

    for port in ports:
        results.append(scan_port(host, port, timeout))

    return results
        
