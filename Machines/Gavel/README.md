# Gavel (Medium) 🟠
<div align="center">
</div>
<img width="256" height="297" src="Images/gavel.png">
</p>

#
Let's get straight to start the reconnaissance phase:
```bash
nmap -sS -vvv -p- --open -n -Pn --min-rate 5000 10.10.11.97 -oG allPorts 
```
```java

# Nmap 7.98 scan initiated Sun Jan 11 14:32:36 2026 as: /usr/lib/nmap/nmap --privileged -sS -vvv -p- --open -n -Pn --min-rate 5000 -oG allPorts 10.10.11.97
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.97 ()    Status: Up
Host: 10.10.11.97 ()    Ports: 22/open/tcp//ssh///, 80/open/tcp//http///    Ignored State: closed (65533)
# Nmap done at Sun Jan 11 14:32:49 2026 -- 1 IP address (1 host up) scanned in 13.30 seconds
```
The page tells us that it has port 22 and port 80 open, so the active services are HTTP and SSH. Let's delve deeper into these ports, as always, to see what else we can learn:

```java
# Nmap 7.98 scan initiated Sun Jan 11 14:37:53 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p22,80 -oN targeted 10.10.11.97
Nmap scan report for gavel.htb (10.10.11.97)
Host is up (0.058s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1f:de:9d:84:bf:a1:64:be:1f:36:4f:ac:3c:52:15:92 (ECDSA)
|_  256 70:a5:1a:53:df:d1:d0:73:3e:9d:90:ad:c1:aa:b4:19 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-git: 
|   10.10.11.97:80/.git/
|     Git repository found!
|     .git/config matched patterns 'user'
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: .. 
|_http-title: Gavel Auction
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
# Nmap done at Sun Jan 11 14:38:03 2026 -- 1 IP address (1 host up) scanned in 9.30 seconds
```
We can see that it reports something like there's a repository hosted on the page with the /git subdirectory, but it's nothing important; there's nothing there that can give us privileged information.
