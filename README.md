# tryhackme-Pyratt-Writeup
![intro](https://github.com/user-attachments/assets/28e04153-3286-4a8a-8d50-29f529071f88)
# tryhackme-Pyratt-Writeup

This is a walkthrough for the tryhackme CTF Pyratt. I will not provide any flags or passwords as this is intended to be used as a guide. Think you're up for the Challange?

## Scanning/Reconnaissance

First off, let's store the target IP as a variable for easy access.

Command: export ip=xx.xx.xx.xx

Next, let's run an nmap scan on the target IP:
```bash
nmap -sV -sC -A -v $ip -oN
```

Command break down:

-sV

Service Version Detection: This option enables version detection, which attempts to determine the version of the software running on open ports. For example, it might identify an HTTP server as Apache with a specific version.
-sC

Default Scripts: This option runs a collection of default NSE (Nmap Scripting Engine) scripts that are commonly useful. These scripts perform various functions like checking for vulnerabilities, gathering additional information, and identifying open services. They’re a good starting point for gathering basic information about a host.
-A

Aggressive Scan: This option enables several scans at once. It combines OS detection (-O), version detection (-sV), script scanning (-sC), and traceroute (--traceroute). It’s useful for a comprehensive scan but can be intrusive and time-consuming.
-v

Verbose Mode: Enables verbose output, which provides more detailed information about the scan’s progress and results.
$ip

Target IP: This is a placeholder for the target IP address you want to scan. In practice, replace $ip with the actual IP of the machine you are targeting.
-oN

Output in Normal Format: This option saves the scan results in a plain text file format. After -oN, specify a filename where you want to store the output.

The scan reveals a simple http web server on port 8000, and ssh.

![nmap](https://github.com/user-attachments/assets/96e6f487-b646-49d4-97a9-f7a41358ce6f)

When visiting the webserver on $ip:8000, there is just a message to "try a more basic connection". 
Let's try to connect via netcat:
```bash
nc $ip 8000
```
After typing in a few cmds and thinking back to nmap showing that this is a python server, we can see that it accepts python cmds ex. print(33+55). 
Let's try inputting a python rev shell from revshells.com. Notice, since it is taking python cmds directly, do not inlude the python -c part of the shell. 

![www-data](https://github.com/user-attachments/assets/20065d7b-f457-4f62-a0c2-d9b4875bae10)

We now have a reverse shell as www-data. We are in the root directory so we don't have permission to ls in this directory. 
Running cat /etc/passwd reveals a user named think. I tried to navigate to home/think but we don't have permission. I then ran the find command to see what files and directories they have, which reveals /opt/dev/.git:

![think](https://github.com/user-attachments/assets/eb724ecd-2c11-406b-8570-102953979d5f)

Navigating to this directory we see a lot of files and dirs and www-data has read access to. The config file reveals credentials for think. Let's try to use these to ssh onto the target.

![ssh_think](https://github.com/user-attachments/assets/8b7b90ba-6939-4856-8c09-42550351c936)

Tbey worked, and we can now reveal the user flag from think's home dir.

