# **Attack Surface Assessment Tool**

## **Overview**
The **Attack Surface Assessment Tool** is a Perl-based security scanner designed to identify, analyze, and report vulnerabilities in web applications and servers. It aligns with key security frameworks such as **OWASP Top 10**, **SANS Top 25**, and **CEH (Certified Ethical Hacker)**, covering over **100 vulnerabilities** and more across various categories.

This tool enables security professionals and penetration testers to proactively identify security flaws and harden systems against cyberattacks.

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
This tool includes, but is not limited to:
- Injection Attacks
- Authentication Flaws
- Sensitive Data Exposure
- Security Misconfigurations
- Cross-Site Scripting (XSS)
- File Inclusion
- Directory Traversal
- API Vulnerabilities
- Client-Side Attacks
- Server-Side Attacks
- Network Misconfigurations
- Cryptographic Weaknesses
- **And More...**
