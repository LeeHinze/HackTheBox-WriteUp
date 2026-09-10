# AHS512

## Challenge summary

The service presents itself as a collision challenge for a modified version of
SHA-512. We are given the digest of a known message and must submit a different
message that produces the same result.

The important part of the server is the custom `ahs512` class. Before calling
the real SHA-512 function, it applies two operations to the input:

1. It rearranges the bytes using a randomly selected divisor of the message
   length.
2. It transforms every byte with a function named `rotate`.

Since SHA-512 itself is not realistically breakable, the collision must come
from one of these preprocessing steps.

## Reviewing the implementation

The target is generated from the following value:

```python
original_message = b"pumpkin_spice_latte!"
original_digest = ahs512(original_message).hexdigest()
```

The final digest is calculated like this:

```python
def hexdigest(self):
    transposed = self.transpose(self.message)
    rotated = self.rotate(transposed)
    return sha512(bytes(rotated)).hexdigest()
```

The transposition is controlled by a random key. For a 21-byte message, the
only possible keys are `3` and `7`, because the key must divide the input
length exactly. This randomness means that two attempts with the same input do
not always produce the same digest.

The actual weakness, however, is in the byte transformation:

```python
def rotate(self, message):
    return [((b >> 4) | (b << 3)) & 0xff for b in message]
```

Despite its name, this is not a proper bit rotation. The shifted values are
combined with OR, causing information to be lost. As a result, different input
bytes can produce the same output byte.

## Building the collision

The original message contains two underscore bytes. An underscore is `0x5f`,
and the transformation produces `0xfd`:

```text
f(0x5f) = ((0x5f >> 4) | (0x5f << 3)) & 0xff
        = 0xfd
```

If its most significant bit is enabled, the byte becomes `0xdf`. It still
produces exactly the same transformed value:

```text
f(0xdf) = ((0xdf >> 4) | (0xdf << 3)) & 0xff
        = 0xfd
```

Therefore, replacing the underscores with `0xdf` gives us a message that is
different from the original while remaining identical after the vulnerable
transformation:

```python
collision = b"pumpkin\xdfspice\xdflatte!"
```

The replacement does not change the message length or byte positions. If the
server chooses the same transposition key that it used for the target digest,
both inputs reach SHA-512 as the same byte sequence. We can simply submit the
collision repeatedly until that happens.

## Solver

The included solver uses only Python's standard library:

```bash
python3 solve.py <host> <port>
```

It waits for the prompt, sends the candidate as hexadecimal, and retries while
the server returns `Conditions not satisfied!`.

```python
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
```

## Flag

```text
HTB{5h4512_8u7_w17h_4_7w157_83f023_c4n_93n32473_c0111510n5}
```

## Takeaway

The SHA-512 call is not the vulnerable component. The custom preprocessing
function maps several byte values to the same result, so the overall
construction loses collision resistance before SHA-512 ever receives the
data. Cryptographic primitives should not be wrapped in lossy transformations
when uniqueness of the original input matters.
