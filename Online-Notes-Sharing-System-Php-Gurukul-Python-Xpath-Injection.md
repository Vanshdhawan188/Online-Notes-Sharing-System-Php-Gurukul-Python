
# 🧾 Vulnerability Report – XPath Injection in Notes Sharing System

**Author:** Subhah Paudel

**Date:** 29 June 2025  
**Target URL:** http://127.0.0.1:8000/Dashboard  
**Project Source:** https://phpgurukul.com/online-notes-sharing-system-using-python-django-and-mysql/

**Vulnerability:** XPath Injection (Authentication Bypass & Data Extraction)  
**Severity:** Critical  
**Technology Stack:** Python, Django, XML-Based Session Auth (likely), HTML/CSS/JS

---

## 📌 Introduction

A critical vulnerability was discovered in the **PHP Gurukul - Online Notes Sharing System**, a web application designed to manage and share academic notes among students and faculty. The vulnerability affects the session management logic handled via cookies and specifically targets the `sessionid` cookie used during authentication and user tracking.

The flaw allows attackers to perform **XPath Injection** by supplying specially crafted values in the `sessionid` cookie. Due to improper neutralization of input within XPath expressions, the application becomes vulnerable to logic manipulation, authentication bypass, and potential data extraction from the backend XML data store (e.g., usernames, passwords).

## 🗂️ Vulnerability Summary

| Field             | Details                                                |
|------------------|--------------------------------------------------------|
| Affected URL     | `/Dashboard`                                           |
| Affected Param   | `sessionid` (via HTTP Cookie)                          |
| Issue Type       | XPath Injection                                        |
| Impact           | Auth bypass, user data exfiltration                    |
| PoC Status       | Confirmed with manual testing                          |
| Authentication   | Bypassed with crafted cookie                           |
| Risk Level       | 🔴 Critical                                             |



## 🔍 Step-by-Step Exploitation (PoC)

### 1️⃣ Step 1: Access the Login Page

Navigate to the following URL:
```
http://127.0.0.1:8000/Login
```
Attempt to log in with these credentials or Create New Account:

Username:  john123

Password: Test@123

![image](https://github.com/user-attachments/assets/229422f1-d426-4cb0-9577-7e3bd1292329)

---

### 2️⃣ Step 2: Intercept /Dashboard Request in Burp

After The Login You Will Be Redirected to access Dashboard, capture the request in **Burp Suite**:
![image](https://github.com/user-attachments/assets/6688a149-2951-4433-989c-ec7c672cb2d0)



### 3️⃣ Step 3: Modify Cookie with XPath Payload

In **Burp Repeater**, modify the `sessionid` to a crafted payload:
![image](https://github.com/user-attachments/assets/4996c885-c94c-4d13-9c7a-07e73b51bcd9)

Modify This Request With This Paylod And Click On Send: 

```
Cookie: sessionid=' or '1'='1
```
![image](https://github.com/user-attachments/assets/44534291-f62c-458c-b18e-b81d99694d64)


### ✅ Bypassed Response:
![image](https://github.com/user-attachments/assets/aa689559-624c-40ff-9946-97cdc3ac2081)

- Returns HTTP 200 OK
- Loads the Dashboard HTML
- You are logged in without valid credentials

---



## ⚠️ Risk Assessment

| Impact Area      | Description                                            |
|------------------|--------------------------------------------------------|
| Auth Bypass      | Unauthenticated attackers can gain user access        |
| Data Exposure    | Usernames and passwords can be extracted               |
| Lateral Movement | Potential to hijack admin sessions                     |
| No Logging       | Session hijack leaves no server logs                   |

---

## 🛠️ Mitigation & Recommendations

### ✅ Input Sanitization
- Use safe libraries that auto-escape XPath values (e.g., parameterized queries)
- Reject or sanitize dangerous characters (`'`, `"`, `or`, `and`, etc.)

### ✅ Secure Session Handling
- Avoid storing sensitive logic like session validation inside XML
- Use encrypted, signed session tokens (e.g., JWTs, Django's signed cookies)

### ✅ Patch Example (Python XPath)

```python
# Vulnerable:
xpath_query = f"//user[sessionid='{session_cookie}']"

# Safe:
xpath_query = "//user[sessionid=$sess]"
xpath.evaluate(xpath_query, document, None, XPathConstants.NODESET, {"sess": session_cookie})
```

---

