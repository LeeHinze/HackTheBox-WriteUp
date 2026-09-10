#!/usr/bin/env python3
import socket
import re
import sys

ROUNDS = 100

class Conn:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.buf = b""

    def recv_until(self, marker, timeout=10):
        self.sock.settimeout(timeout)
        while marker.encode() not in self.buf:
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            self.buf += data
        if marker.encode() in self.buf:
            idx = self.buf.index(marker.encode()) + len(marker)
            chunk = self.buf[:idx]
            self.buf = self.buf[idx:]
            return chunk.decode(errors="ignore")
        chunk = self.buf.decode(errors="ignore")
        self.buf = b""
        return chunk

    def send_line(self, line):
        self.sock.sendall((line + "\n").encode())

    def close(self):
        self.sock.close()


def parse_round(text):
    """
    Parses a round block and returns the winning player's number (str).
    Expected line format:
    Player 1: 3 5 2 6 ...
    """
    players = {}
    for line in text.splitlines():
        m = re.match(r"Player (\d+): (.+)", line.strip())
        if m:
            pnum = int(m.group(1))
            dice = [int(x) for x in m.group(2).split()]
            players[pnum] = sum(dice)

    if not players:
        return None

    max_score = max(players.values())
    
    winners = [p for p, s in players.items() if s == max_score]
    winner = max(winners)
    return str(winner)


def main():
    quiet = "--quiet" in sys.argv
    if quiet:
        sys.argv.remove("--quiet")

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port> [--quiet]")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    conn = Conn(host, port)

    intro = conn.recv_until("> ")
    print(intro)
    conn.send_line("1")

    banner = conn.recv_until("-----------")
    print(banner)

    for i in range(ROUNDS):
        block = conn.recv_until("> ")
        if not quiet:
            print(f"--- Round {i+1} ---")
            print(block)
        elif (i + 1) % 10 == 0:
            print(f"[progress] round {i+1}/{ROUNDS}")

        winner = parse_round(block)
        if winner is None:
            print("[!] Could not parse the round, aborting.")
            print(conn.recv_until("", timeout=3))
            conn.close()
            sys.exit(1)

        if not quiet:
            print(f"[+] Answering winning player: {winner}")
        conn.send_line(winner)

    print("--- Waiting for final result ---")
    conn.sock.settimeout(15)
    final = b""
    try:
        while True:
            chunk = conn.sock.recv(65536)
            if not chunk:
                break
            final += chunk
    except socket.timeout:
        pass

    print(final.decode("utf-8", errors="replace"))
    conn.close()


if __name__ == "__main__":
    main()
