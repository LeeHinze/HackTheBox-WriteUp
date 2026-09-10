# Interstellar C2

## Overview

**Interstellar C2** is a Hack The Box forensic challenge that provides a
network capture named `capture.pcapng`. The goal is not to search for the flag
directly among the strings in the file, but to reconstruct a multi-stage
infection and understand how the implant exchanges commands and results with
its command-and-control server.

The investigation involves obfuscated PowerShell, AES encryption, .NET
assemblies, **PoshC2** traffic, and data disguised as PNG images.

## 1. Initial traffic analysis

We begin by opening the capture in Wireshark and applying a simple filter:

```text
http
```

The HTTP conversation quickly reveals the remote host `64.226.84.200`. The
first relevant stage downloads a script named `vn84.ps1`. Shortly afterward,
the same machine requests another resource whose name resembles a UUID:

```text
http://64.226.84.200/94974f08-5853-41ab-938a-ae1bd86d8e51
```

Both objects can be recovered through `File > Export Objects > HTTP` or by
using `Follow HTTP Stream`. The infection chain that we need to reconstruct is:

```text
vn84.ps1 -> AES payload -> .NET implant -> PoshC2 commands
          -> encrypted responses inside PNG files -> screenshot containing the flag
```

## 2. Deobfuscating the PowerShell loader

The contents of `vn84.ps1` are difficult to read because names are split into
fragments, uppercase and lowercase letters are mixed, and commands are built
with the `-f` format operator. For example:

```powershell
"{1}{0}{2}" -f 'T','Set-i','em'
```

PowerShell evaluates this expression as `Set-Item`. There is no need to
normalize the entire script. Resolving only the expressions related to the
download and decryption is enough to reduce its behavior to the following
steps:

1. Download the UUID-named resource with `Start-BitsTransfer`.
2. Initialize AES with a key and IV embedded in the script.
3. Decrypt the response in memory.
4. Save the result as `%TEMP%\tmp7102591.exe`.
5. Execute the newly created binary.

The key and initialization vector are both 16-byte arrays:

```python
key = bytes((0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0))
iv  = bytes((0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1))
```

We export the body of the second HTTP response as `payload.bin` and reproduce
the decryption process in Python:

```python
from Crypto.Cipher import AES

key = bytes((0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0))
iv = bytes((0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1))

with open("payload.bin", "rb") as source:
    encrypted = source.read()

malware = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted)

with open("malware.exe", "wb") as output:
    output.write(malware)
```

The first recovered bytes are `4d 5a`, the `MZ` signature of a Windows
executable. The `file` command provides an even more useful detail:

```text
malware.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly
```

This is a .NET assembly, so it can be inspected with dnSpy, ILSpy, or dotPeek
without executing the sample.

## 3. Understanding the .NET implant

The main function hides the console and calls `primer()`. This function
collects information from the compromised system using the following format:

```text
domain;user;computer;architecture;PID;process;1
```

It then contacts the following C2 path:

```text
/Kettie/Emmie/Anni?Theda=Merrilee?c
```

The host information is not sent as a visible parameter. The implant encrypts
it and places it inside a cookie:

```http
Cookie: SessionID=<Base64(IV + AES-CBC(data))>
```

The key used during this stage is stored as Base64 inside the binary:

```text
DGCzi057IDmHvgTVE2gm60w8quqfpMD+o8qCBGpYItc=
```

Decrypting the cookie found in the capture produces:

```text
DESKTOP;DESKTOP\IEUser*;DESKTOP;AMD64;6796;tmp7102591;1
```

The asterisk appended to the username indicates that the process is running in
a high-integrity context.

## 4. Recovering the configuration

The response from `/Kettie/Emmie/Anni` is encrypted as well. Its structure is:

```text
Base64(IV + AES-CBC(Base64(configuration)))
```

The data must therefore be Base64-decoded both before and after applying AES.
The following helper function avoids repeating the process for every packet:

```python
from base64 import b64decode
from Crypto.Cipher import AES


def decrypt_c2(value, key_b64, inner_base64=True):
    raw = b64decode(value)
    iv, ciphertext = raw[:16], raw[16:]
    key = b64decode(key_b64)
    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    plaintext = plaintext.rstrip(b"\x00")
    return b64decode(plaintext) if inner_base64 else plaintext
```

The recovered text contains several values enclosed by custom markers,
including `RANDOMURI`, `URLS`, `KILLDATE`, `SLEEP`, `JITTER`, `NEWKEY`, and
`IMGS`. The most important values are:

```text
KILLDATE = 2025-01-01
SLEEP    = 3s
JITTER   = 0.25
NEWKEY   = nUbFDDJadpsuGML4Jxsq58nILvjoNu76u4FIHVGIKSQ=
```

`URLS` contains a long list of paths used by the malware to make its beacons
look like ordinary requests. `IMGS` stores small Base64-encoded images that
will serve as carriers during exfiltration. From this point onward, `NEWKEY`
must be used to decrypt commands and their responses.

## 5. Identifying PoshC2

One of the next GET responses decrypts to a message beginning with:

```text
multicmd00031loadmoduleTVqQAA...
```

The string `TVqQAA` is the usual Base64 beginning of a PE file with an `MZ`
header. The implant removes the `loadmodule` prefix, decodes the assembly, and
loads it directly with `Assembly.Load()` without writing it to disk.

After extracting and decompiling the module, namespaces such as `Core.Program`
and `Core.Common` appear alongside commands associated with **PoshC2**. This
explains the random URL list, the `multicmd` structure, and the periodic task
exchange visible in the capture.

## 6. Exfiltration disguised as images

Commands arrive through GET requests, while their results are returned through
POST requests. Although the POST bodies begin as PNG images, the
`ImgGen.GetImgData()` method reveals how the data is hidden:

1. Select one of the images included in the configuration.
2. Add filler characters until the data reaches 1500 bytes.
3. Append the encrypted response at that offset.

The image still opens normally because parsers ignore bytes located after the
logical end of the PNG file. To recover the useful data, we only need to remove
the first 1500 bytes. The remaining content uses this structure:

```text
IV (16 bytes) || AES-CBC(GZIP(result))
```

The extraction of any POST response exported from Wireshark can be automated:

```python
from base64 import b64decode
from gzip import decompress
from Crypto.Cipher import AES

KEY = b64decode("nUbFDDJadpsuGML4Jxsq58nILvjoNu76u4FIHVGIKSQ=")


def extract_result(path):
    with open(path, "rb") as source:
        encrypted = source.read()[1500:]

    iv, ciphertext = encrypted[:16], encrypted[16:]
    plaintext = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ciphertext)
    return decompress(plaintext.rstrip(b"\x00"))


print(extract_result("image3.png").decode(errors="replace"))
```

Running it against one of the first POST requests recovers a monitor power
event:

```text
WM_POWERBROADCAST:GUID_MONITOR_POWER_ON:On
```

This confirms that the offset, the new key, and the order of the transformations
are correct.

## 7. Commands executed by the attacker

The next relevant task contains two chained instructions. It first loads
another assembly and then invokes SharpSploit to execute Mimikatz:

```text
loadmodule <Base64 assembly>
run-dll SharpSploit.Credentials.Mimikatz SharpSploit Command
"privilege::debug sekurlsa::logonPasswords"
```

Processing the associated POST request reveals the complete Mimikatz output.
The results include the interactive session for `DESKTOP\IEUser` and its NTLM
hash, proving that the attacker attempted to extract credentials from LSASS
memory.

The final relevant command is much more direct:

```text
multicmd00036get-screenshot
```

Its response is the largest POST request in the capture. We apply the same
procedure: remove the first 1500 carrier bytes, separate the IV, decrypt the
data with AES, and decompress it with GZIP. This time, the result is another
Base64 string:

```python
from base64 import b64decode

screenshot = b64decode(extract_result("image6.png"))

with open("screenshot.png", "wb") as output:
    output.write(screenshot)
```

The signature `89 50 4e 47 0d 0a 1a 0a` confirms that another PNG image has
been reconstructed. When `screenshot.png` is opened, the flag is visible in
the upper-right corner of the captured desktop.

## Flag

```text
HTB{h0w_c4N_y0U_s3e_p05H_c0mM4nd?}
```

## Conclusion

The key to solving the challenge is following each layer in the correct order,
not breaking the encryption. Every required key and transformation is exposed
by either the loader or the implant:

```text
HTTP -> AES -> .NET -> Base64 -> AES -> GZIP -> PNG
```

Once the protocol has been reconstructed, the apparently harmless images
become a record of the attacker's actions: loading modules, executing Mimikatz,
and taking a screenshot. The challenge demonstrates why validating the real
structure and size of transferred files can be just as important as inspecting
their visible contents during network analysis.
