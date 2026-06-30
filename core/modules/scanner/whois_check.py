import socket


def whois_ip(ip: str) -> str:
    s = socket.create_connection(("whois.cymru.com", 43), timeout=5)
    s.send(f" -v {ip}\r\n".encode())
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return data.decode(errors="ignore")


if __name__ == "__main__":
    print(whois_ip("188.137.254.225"))
