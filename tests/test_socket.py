import socket

host = "127.0.0.1"
port = 80
timeout = 2

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
        print(f"[+] Port {port} is open on host {host}")

    except ConnectionRefusedError:
        print(f"[-] Port {port} is closed on host {host}")

    except socket.timeout:
        print(f"[?] Port {port} timed out on host {host}")

    except OSError as error:
        print(f"[!] Network error: {error}")