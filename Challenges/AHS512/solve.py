#!/usr/bin/env python3
import socket
import sys


PROMPT = b"Enter your message: "
FAILURE = b"Conditions not satisfied!"
COLLISION = b"pumpkin\xdfspice\xdflatte!".hex().encode()


def receive_until(sock, marker):
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("The server closed the connection")
        data.extend(chunk)
    return bytes(data)


def solve(host, port):
    with socket.create_connection((host, port)) as sock:
        receive_until(sock, PROMPT)

        while True:
            sock.sendall(COLLISION + b"\n")
            response = receive_until(sock, PROMPT)

            if FAILURE not in response:
                print(response.decode(errors="replace").strip())
                return


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} <host> <port>")

    solve(sys.argv[1], int(sys.argv[2]))
