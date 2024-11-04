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

-A: This flag enables aggressive scanning. It combines various scan types (like OS detection, version detection, script scanning, and traceroute) into a single scan.

-v: increases verbosity, providing more detailed output during the scan.

—$ip: provides the target IP we stored as the variable $ip.

-oN nmap.txt: This option specifies normal output that should be saved to a file named “nmap.txt.
