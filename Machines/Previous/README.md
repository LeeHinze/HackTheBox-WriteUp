# Previous (Medium) 🟠
<div align="center">
</div>
<img width="256" height="297" src="images/Previous.png">
</p>

As always, I start with the usual process, the scanning phase.
```bash
# Nmap 7.93 scan initiated Fri Dec 26 00:22:27 2025 as: nmap -sS -vvv -n --min-rate 5000 -p- --open -oG allPorts 10.10.11.83
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.83 ()	Status: Up
Host: 10.10.11.83 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
# Nmap done at Fri Dec 26 00:22:41 2025 -- 1 IP address (1 host up) scanned in 13.73 seconds
```
Ports 22 and 80, the HTTP service, and the SSH service are reported.
```bash
Ports 22 and 80, the HTTP service, and the SSH service are reported.
Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-26 00:28 UTC
Nmap scan report for previous.htb (10.10.11.83)
Host is up (0.059s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: PreviousJS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.31 seconds
```
The page title says `PreviousJs`, so it's pretty clear that everything listed needs to be searched for on the page. So, let's search for "PreviousJs CVE," and we'll find that the vulnerability to exploit is `CVE 2025-29927`. I used curl to exploit it, using the URL and the exploit with the -H parameter.

You should see a URL where you'll need to do the same thing. Then, you'll need to search for a username and password; the username is Jeremy. Next, we'll establish an SSH connection in the console to `ssh jeremy@previous.htb`, enter the password, and you'll automatically be logged in. There you'll find the user flag on user.txt.

<div align="center">
</div>
<img width="800" height="800" src="images/ssh%40jeremy.png">
</p>

So now we're going to escalate privileges to root, so let's put `sudo -l`.

<div align="center">
</div>
<img width="800" height="800" src="images/sudo%20-l.png">
</p>

We're going to go to the `/opt/examples` location and look at the main.tf.
### (Main.tf)
```tf
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
    }
  }
}

variable "source_path" {
  type = string
  default = "/root/examples/hello-world.ts"

  validation {
    condition = strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")
    error_message = "The source_path must contain '/root/examples/'."
  }
}

provider "examples" {}

resource "examples_example" "example" {
  source_path = var.source_path
}

output "destination_path" {
  value = examples_example.example.destination_path
}

```
We'll have to look into Terraform's environment variables
