# Keep Tryin'

## Challenge overview

**Keep Tryin'** is a Hack The Box forensics challenge in which we are given a
PCAP containing TCP traffic, HTTP messages, and suspicious DNS queries. The
goal is to correlate the information hidden in the HTTP and DNS traffic and
recover the exfiltrated file.

The capture can be inspected with Wireshark. The two most useful display
filters are:

```text
http
dns
```

## 1. Inspecting the HTTP traffic

Filtering for HTTP reveals two interesting messages. The first contains the
following text:

```text
TryHarder
```

On its own, this does not reveal much, but it is worth keeping because it may
be a password or encryption key.

The second message contains a Base64-encoded value:

```text
S2VlcCB0cnlpbmcsIGJ1ZmZ5Cg==
```

We can decode it from the command line:

```bash
echo 'S2VlcCB0cnlpbmcsIGJ1ZmZ5Cg==' | base64 -d
```

```text
Keep trying, buffy
```

This is only a hint, so the next step is to inspect the DNS traffic.

## 2. Analysing the DNS queries

The DNS requests stand out because their subdomains are unusually long and
appear to contain encoded data. One of the values is:

```text
c2VjcmV0LnR4dHwx
```

Decoding it as Base64 gives us:

```bash
echo 'c2VjcmV0LnR4dHwx' | base64 -d
```

```text
secret.txt|1
```

This result provides two important clues:

- `secret.txt` is the name of the transferred file.
- `1` appears to be a sequence number for the DNS data chunk.

The other suspicious query contains a much longer value. Its characters,
especially `-` and `_`, indicate that it uses the URL-safe Base64 alphabet.
The dots inserted between DNS labels belong to the DNS transport and must be
handled when reconstructing the encoded payload.

## 3. Recovering the payload

The clues collected so far tell us how to process the long DNS value:

1. Reassemble the data carried in the DNS query.
2. Decode it using URL-safe Base64.
3. Decrypt the result with RC4.
4. Use `TryHarder`, recovered from the HTTP traffic, as the RC4 key.

This can be reproduced in
[CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64%28%27A-Za-z0-9-_%27,true,false%29RC4%28%7B%27option%27:%27UTF8%27,%27string%27:%27TryHarder%27%7D,%27Latin1%27,%27Latin1%27%29Detect_File_Type%28true,true,true,true,true,true,true/disabled%29Unzip%28%27%27,false%29),
using the following recipe:

```text
From Base64 (URL-safe alphabet)
RC4 (key: TryHarder)
Detect File Type
Unzip
```

After the Base64 decoding and RC4 decryption, the output begins with the
signature `PK`. These are the magic bytes used by ZIP archives, confirming
that the recovered DNS payload is a compressed file.

## 4. Extracting the archive

Enabling the **Unzip** operation in CyberChef extracts a file named
`secret.txt`, matching the filename discovered in the first DNS query. Its
contents reveal the flag:

```text
HTB{$n3aky_DN$_Tr1ck$}
```

## Conclusion

The challenge distributes the information required for recovery across two
protocols. HTTP provides both a hint and the RC4 key, while DNS carries the
filename metadata and encrypted file data. By correlating those artefacts, we
can reconstruct the complete chain:

```text
HTTP: TryHarder
        |
        v
DNS payload -> URL-safe Base64 -> RC4 -> ZIP -> secret.txt -> flag
```

The main takeaway is that long, high-entropy DNS labels can be a sign of DNS
tunnelling or data exfiltration. They should be analysed together with the
rest of the capture, since apparently harmless traffic may contain the key
needed to decode them.
