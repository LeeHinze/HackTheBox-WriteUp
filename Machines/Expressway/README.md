<div align="center">
  <p style="font-size: 520px; margin: 0;">
    <h1> <b>Expressway</b> </h1>
  </p>
</div>
    
<p align="center">
  <img width="256" height="297" src="images/Expressway.png" alt="Expressway">
</p>
## Well, this machine didn't seem too complicated to me, to be honest.
You have to do the reconnaissance phase, including scanning the UDP ports (using `-sU` in `nmap`), and that's where you'll discover what you'll need to use. 

You can use either `hashcat` or `john`, whichever you prefer, but in my case, I used `hashcat` to decrypt the hash using a dictionary. After that, I had to establish an SSH connection with the machine, and you'll have to exploit a vulnerability in the machine.

I'll just add the nmap report:
```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.87 -oG allPorts
```

```java
# Nmap 7.95 scan initiated Sun Nov 30 10:21:59 2025 as: /usr/lib/nmap/nmap --privileged -sS -vvv --min-rate 5000 -Pn -p- --open -oG allPorts 10.10.11.87
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.87 (expressway.htb)      Status: Up
Host: 10.10.11.87 (expressway.htb)      Ports: 22/open/tcp//ssh///
# Nmap done at Sun Nov 30 10:22:16 2025 -- 1 IP address (1 host up) scanned in 16.88 seconds`
```
And then I will go deeper about port '22': 
```bash
nmap -sCV -p22 10.10.11.87 -oN targeted
```

```java
# Nmap 7.95 scan initiated Sun Nov 30 12:46:26 2025 as: /usr/lib/nmap/nmap --privileged -sCV -p22 -oN targeted 10.10.11.87
Nmap scan report for expressway.htb (10.10.11.87)
Host is up (0.053s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 30 12:46:28 2025 -- 1 IP address (1 host up) scanned in 2.25 seconds
```
After that you'll need to do a `nmap` UDP scan, and then you will discover what you will need to use, when you see the UDP port.
```bash
nmap expressway.htb -sU --top-ports 100 -oG udpPorts
```

```java
Nmap scan report for expressway.htb (10.10.11.87)
Host is up (0.055s latency).
Not shown: 96 closed udp ports (port-unreach)
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike
Nmap done: 1 IP address (1 host up) scanned in 124.26 seconds
```
---
## 📝 Final Review: 
I liked the machine, it's not my first time on HackTheBox. 
I've completed some before, but my account is gone and the machines are no longer active. 

But I liked it, I found it fun. Good luck completing it.



