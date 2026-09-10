# Editor (Easy) 🟢
<div align="center">
</div>
<img width="256" height="297" src="images/Editor.png">
</p>

## This machine has become more complicated for me, and I will explain why below.
As always, it is essential to perform the reconnaissance phase, and the ports that appear open are the following:

```bash
nmap -sS -vvv --min-rate 5000 -Pn -p- --open -n 10.10.11.80 -oG allPorts
```
I used the `-n` parameter to deny the DNS Resolution.
```java
# Nmap 7.95 scan initiated Fri Dec  5 12:06:08 2025 as: /usr/lib/nmap/nmap --privileged -sS -vvv --min-rate 5000 -Pn -p- --open -oG allPorts 10.10.11.80
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.80 (editor.htb)  Status: Up
Host: 10.10.11.80 (editor.htb)  Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 8080/open/tcp//http-proxy///
# Nmap done at Fri Dec  5 12:06:21 2025 -- 1 IP address (1 host up) scanned in 13.56 seconds
```
And now we're going to delve deeper into the ports.
```java
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Editor - SimplistCode Pro
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http    Jetty 10.0.20
| http-title: XWiki - Main - Intro
|_Requested resource was http://editor.htb:8080/xwiki/bin/view/Main/
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
|_http-server-header: Jetty(10.0.20)
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Server Type: Jetty(10.0.20)
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec  5 12:08:01 2025 -- 1 IP address (1 host up) scanned in 11.75 seconds
```
Port `8080` tells us about XWiki, so let's put this in the browser: `http://editor.htb:8080`

<div align="center">
</div>
<img width="1920" height="297" src="images/XWiki%20Version.png">
</p>

You'll see that the XWiki version is outdated, so you'll have to look for a vulnerability associated with it, `CVE-2025-24893`

From there you'll have to do a couple more things. You'll have to exploit the vulnerability on port `1337` and use `netcat`, specifically in another window `nc -lnvp 1337`. Then you'll have access to the XWiki page. Later, since there are many files, I'll provide the path where the password is located. You'll have to grep each XML file until you
find the `password`, this is the path `/usr/lib/xwiki/WEB-INF`

I won't say anything more. I've made the first few things easier, since they're not so complicated. Now I'll explain what I found so difficult.

## What was the most complicated part?
After doing everything I said before, you have to connect via `SSH` to a user with the IP address at the end, in this format `******@10.10.11.80`. When you do that and enter the password you should have found by searching with grep, you will get the `flag.txt`, but now the complicated part is to escalate privileges. I won't spoil anymore.

## 📝 Final Review: 

I liked it, but it got complicated and I spent a couple of hours trying to figure out what to do.

it was difficult for my second lab. I made a brief summary, in case I want to do it again to recap, and for users who want a guide.





