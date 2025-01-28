# **Attack Surface Assessment Tool**
- Created by: Haroon Awan
- Email: haroon@cyberzeus.pk

  
## **Overview**
The **Attack Surface Assessment Tool** is a Perl-based security scanner designed to identify, analyze, and report vulnerabilities in web applications and servers. It aligns with key security frameworks such as **OWASP Top 10**, **SANS Top 25**, and **CEH (Certified Ethical Hacker)**, covering over **100 vulnerabilities** and more across various categories.

This tool enables security professionals and penetration testers to proactively identify security flaws and harden systems against cyberattacks.

## **How it scans**
- It does not provide crawl feature, please use specific endpoint or api, (Yes, crawl feature is possible, but I do not see it's use, as CLI can be passed using loop on this tool)
- Example: perl asat.pl --url http://testphp.vulnweb.com/showimage.php?file=

---

## **Vulnerabilities Scanned**

### **OWASP Top 10:**
1. **Injection Attacks**  
   - SQL Injection, Command Injection, LDAP Injection, XPath Injection, and more.
2. **Broken Authentication**  
   - Weak password policies, credential stuffing vulnerabilities, and more.
3. **Sensitive Data Exposure**  
   - Poor encryption, weak TLS/SSL configurations, and more.
4. **XML External Entity (XXE)**  
   - Exploiting XML parsers to retrieve sensitive files.
5. **Broken Access Control**  
   - Privilege escalation, directory traversal, and more.
6. **Security Misconfigurations**  
   - Unnecessary services, open directories, and insecure headers.
7. **Cross-Site Scripting (XSS)**  
   - Reflective, Stored, DOM-based XSS, and more.
8. **Insecure Deserialization**  
   - Executing untrusted or tampered serialized data.
9. **Using Components with Known Vulnerabilities**  
   - Libraries, frameworks, and packages.
10. **Insufficient Logging and Monitoring**  
    - Identifying gaps in event logging.

### **SANS Top 25 Most Dangerous Software Errors:**
1. **Improper Input Validation**  
   - Fuzzing-based detection of invalid inputs.
2. **Buffer Overflows**  
   - Testing stack and heap overflow scenarios.
3. **Race Conditions**  
   - Detecting vulnerabilities in concurrent processes.
4. **Improper Authorization**  
   - Privilege escalation testing.
5. **Hardcoded Credentials**  
   - Detection of default or hardcoded passwords.
6. **Path Traversal and File Inclusion**  
   - Locating unauthorized access points, and more.

### **CEH Topics:**
1. **Web Application Attacks**  
   - SQL Injection, XSS, RFI/LFI, directory traversal, and more.
2. **Network Security Testing**  
   - Port scanning, enumeration, and more.
3. **Authentication Bypasses**  
   - Credential brute-forcing, session hijacking, and more.
4. **Misconfigured Servers and Services**  
   - Open ports, exposed sensitive data, and more.
5. **Vulnerable API Endpoints**  
   - Discovering and testing insecure APIs.

---

## **Scan Capabilities**
The tool supports advanced scanning techniques and can detect over **100 vulnerabilities and more**, leveraging various payloads and algorithms:

1. **Injection Attacks**  
   - SQL, LDAP, Command, XPath, XML, and more.
2. **Cross-Site Scripting (XSS)**  
   - Reflective, Stored, and DOM-based XSS detection.
3. **Authentication Flaws**  
   - Weak credentials, login bypasses, and more.
4. **Sensitive Data Exposure**  
   - Identifying weak encryption, HTTPS misconfigurations, and more.
5. **Security Misconfigurations**  
   - Open directories, insecure headers, and more.
6. **File Inclusion**  
   - Local and Remote File Inclusion vulnerabilities.
7. **Directory Traversal**  
   - Attempting unauthorized file access, and more.
8. **Vulnerable APIs and Web Services**  
   - Testing API endpoints for insecure practices.

---

## **Framework Alignment**
The tool aligns with the following frameworks to provide comprehensive coverage:

1. **OWASP Top 10**  
   - Detects and reports vulnerabilities mapped to OWASP categories.
2. **SANS Top 25 Most Dangerous Software Errors**  
   - Focuses on the most critical software issues.
3. **CEH (Certified Ethical Hacker)**  
   - Incorporates common penetration testing techniques taught in CEH.

---

## **Features**
1. **Crawling and Deep Scanning**  
   - Extracts and scans all links within the same domain.
2. **Payload Injection**  
   - Tests inputs with payloads like `SQL_Injection.txt` and `XSS_Injection.txt`.
3. **Pattern Matching**  
   - Detects vulnerabilities based on known signatures and anomalies.
4. **Active and Passive Scanning**  
   - Offers flexibility in testing methodologies.
5. **Detailed Reporting**  
   - Logs vulnerabilities with actionable insights.

---

## **How It Works**
1. **Input URL**  
   - The script accepts a target URL (`--url`) for scanning.
2. **Payload Testing**  
   - Automatically injects payloads to test for vulnerabilities.
3. **Regex Matching**  
   - Identifies vulnerable responses using regular expressions.
4. **Database Logging**  
   - Logs all findings into a structured database.
5. **Comprehensive Output**  
   - Outputs results mapped to OWASP, SANS, and CEH categories.

---

## **Why Choose This Tool?**
- **Comprehensive Vulnerability Coverage**  
  - Scans over **100 vulnerabilities and more** across web applications, APIs, and servers.
- **Alignment with Industry Standards**  
  - Mapped to **OWASP Top 10**, **SANS Top 25**, and **CEH**.
- **Proactive Defense**  
  - Identifies vulnerabilities before attackers exploit them.
- **Detailed Reporting**  
  - Generates logs with actionable insights for remediation.

---

## **Supported Vulnerability Categories**

This tool includes, but is not limited to, comprehensive detection of vulnerabilities across diverse attack vectors and categories. Below are the detailed categories:

### **1. Injection Attacks**
- **SQL Injection**: Identifies vulnerabilities in SQL queries allowing attackers to manipulate database queries.
- **Command Injection**: Detects unauthorized execution of system commands on the server.
- **LDAP Injection**: Identifies flaws in LDAP queries that allow unauthorized access.
- **XPath Injection**: Finds vulnerabilities in XML XPath queries.
- **XML Injection**: Detects manipulation of XML data structures.
- **NoSQL Injection**: Detects attacks on modern databases like MongoDB and CouchDB.

### **2. Authentication Flaws**
- **Weak Passwords**: Identifies login systems with weak or no password policies.
- **Session Hijacking**: Detects vulnerabilities allowing session token theft.
- **Default Credentials**: Checks for applications using default or hardcoded credentials.
- **Multi-Factor Authentication Bypass**: Tests for flaws in 2FA/MFA implementations.
- **Credential Stuffing Vulnerabilities**: Identifies systems vulnerable to brute-force login attempts.

### **3. Sensitive Data Exposure**
- **Weak Encryption**: Detects use of deprecated algorithms like MD5 and SHA1.
- **Exposed APIs**: Identifies sensitive API responses leaking sensitive data.
- **HTTP Usage**: Flags endpoints not using HTTPS.
- **Insecure Cookies**: Detects unprotected session cookies (missing `Secure` or `HttpOnly` flags).

### **4. Security Misconfigurations**
- **Exposed Directories**: Identifies directory listings left open unintentionally.
- **Default Configurations**: Finds applications running with default or insecure configurations.
- **Missing Security Headers**: Detects missing HTTP security headers (e.g., CSP, HSTS).
- **Unnecessary Ports and Services**: Flags open ports and unnecessary running services.
- **Weak File Permissions**: Identifies files or directories with insecure permissions.

### **5. Cross-Site Scripting (XSS)**
- **Reflected XSS**: Detects input reflected in the response without sanitization.
- **Stored XSS**: Identifies payloads stored persistently in databases or files.
- **DOM-Based XSS**: Tests for vulnerabilities in client-side JavaScript.

### **6. File Inclusion**
- **Local File Inclusion (LFI)**: Identifies vulnerabilities allowing unauthorized file access on the server.
- **Remote File Inclusion (RFI)**: Detects injection of remote files into application execution.

### **7. Directory Traversal**
- **Path Traversal**: Flags attempts to access unauthorized directories.
- **Unauthorized File Access**: Detects vulnerabilities exposing sensitive configuration files (e.g., `config.php`, `.env`).

### **8. API Vulnerabilities**
- **Broken Object-Level Authorization**: Finds APIs vulnerable to object-level privilege escalation.
- **Insecure Endpoints**: Identifies API endpoints lacking proper authentication.
- **Rate Limiting Flaws**: Detects endpoints without request throttling.
- **Excessive Data Exposure**: Finds APIs returning more data than necessary.
- **Mass Assignment**: Tests for unprotected fields in API request payloads.

### **9. Client-Side Attacks**
- **DOM Manipulation**: Identifies attacks altering client-side scripts.
- **Clickjacking**: Tests for the presence of vulnerable iframe implementations.
- **Insecure CORS Configurations**: Detects improperly configured CORS policies allowing unauthorized cross-origin access.
- **JavaScript Injection**: Detects injection of malicious scripts via user inputs.

### **10. Server-Side Attacks**
- **Server-Side Request Forgery (SSRF)**: Identifies vulnerabilities allowing unauthorized server requests.
- **Server-Side Template Injection (SSTI)**: Detects insecure template rendering systems.
- **Deserialization Flaws**: Tests for vulnerabilities in handling serialized objects.
- **Shell Injection**: Detects unauthorized execution of shell commands.

### **11. Network Misconfigurations**
- **Open Ports**: Scans for unnecessary open ports.
- **Weak Network Encryption**: Identifies networks using outdated encryption protocols like WEP or WPA1.
- **Misconfigured Firewalls**: Detects improperly configured firewall rules allowing unauthorized access.

### **12. Cryptographic Weaknesses**
- **Weak Encryption Protocols**: Flags outdated cryptographic protocols like SSLv3.
- **Broken Key Exchange**: Identifies weak Diffie-Hellman or RSA key exchanges.
- **Missing Certificates**: Tests for applications running without proper SSL/TLS certificates.
- **Insecure Storage**: Detects sensitive data stored without encryption.

### **13. Vulnerable APIs and Web Services**
- **SOAP Vulnerabilities**: Identifies flaws in SOAP-based web services.
- **REST API Weaknesses**: Tests for missing authentication and validation in REST APIs.
- **GraphQL Vulnerabilities**: Scans GraphQL endpoints for unrestricted queries and sensitive data leaks.

### **14. Client-Side and JavaScript Vulnerabilities**
- **DOM-Based Attacks**: Identifies untrusted client-side inputs leading to DOM manipulation.
- **JavaScript Source Exposure**: Detects client-side JavaScript leaking sensitive information.
- **JSON Injection**: Tests for injection vulnerabilities in JSON-based communication.

### **15. Cross-Origin Resource Sharing (CORS)**
- **Insecure Policies**: Identifies overly permissive cross-origin rules.
- **Cross-Domain Request Forgery**: Detects vulnerabilities allowing unauthorized cross-domain requests.

### **16. Malware Injection Points**
- **Malicious Script Hosting**: Finds injection points for malicious scripts.
- **Backdoor Detection**: Identifies application backdoors allowing remote access.

### **17. Session Management Flaws**
- **Session Fixation**: Tests if the application allows fixation of session tokens.
- **Session Timeout Mismanagement**: Detects overly long or non-expiring session durations.
- **Exposed Session Tokens**: Flags session tokens transmitted over insecure channels.

### **18. Business Logic Vulnerabilities**
- **Logic Flaws**: Detects misuse of application workflows to bypass rules or escalate privileges.
- **Race Conditions**: Identifies flaws when multiple requests interfere with each other.

### **19. Mobile-Specific Vulnerabilities**
- **Insecure Storage**: Tests for sensitive data storage in plain text.
- **Weak Authentication**: Detects improper implementation of biometrics or PINs.
- **Insecure Data Transmission**: Identifies apps transmitting sensitive data over insecure channels.

### **20. Advanced Threat Detection**
- **Zero-Day Vulnerability Detection**: Identifies patterns that could indicate potential zero-day vulnerabilities.
- **Social Engineering Points**: Flags features vulnerable to phishing or social engineering attacks.

### **21. And More...**
- **Custom Payloads**: Enables scanning with user-defined payloads.
- **Browser-Specific Attacks**: Tests vulnerabilities related to outdated browser plugins or extensions.
- **Cloud Vulnerabilities**: Scans for misconfigured storage buckets and exposed cloud services.
- **IoT Vulnerabilities**: Tests security weaknesses in connected devices.

