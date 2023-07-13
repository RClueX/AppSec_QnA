**`What are the Diffrent types of XXE?and Recommendations ?`**

There are basically two types of XXE attacks

- In Band XXE: In-band XXE attacks are more common and let the attacker receive an immediate response to the XXE payload.

- Out Of Band XXE (Blind XXE): in the case of out-of-band XXE attacks (also called blind XXE), there is no immediate response from the web application.
```
Reference: https://www.acunetix.com/blog/articles/xml-external-entity-xxe-vulnerabilities/
```
---

**`What is Insecure Deserialization, How to Detect them in Black box & white box Testing and Recommendations ?`**

Insecure deserialization is a vulnerability that occurs when an application or system blindly trusts and processes serialized data from untrusted sources without proper validation. Deserialization is the process of converting serialized data, such as JSON or XML, back into its original form. Attackers can exploit insecure deserialization to execute arbitrary code, bypass security controls, and escalate privileges.

To detect insecure deserialization vulnerabilities, both black box and white box testing techniques can be employed:

1. Black Box Testing:
   - Input Fuzzing: Provide unexpected or malicious input during deserialization and observe the application's behavior. Look for any crashes, error messages, or unusual responses.
   - Input Tampering: Modify serialized data and examine how the application handles unexpected changes. Monitor for any unexpected behaviors or security exceptions.
   - Boundary Testing: Test edge cases and extreme values for serialized data to identify potential vulnerabilities. Examples include empty inputs, large data sizes, or unexpected data types.

2. White Box Testing:
   - Source Code Review: Analyze the application's source code to identify insecure deserialization points. Look for deserialization functions and check if they perform proper validation and sanitization of serialized data.
   - Static Code Analysis: Utilize automated tools to scan the codebase for potential insecure deserialization vulnerabilities. These tools can detect common coding patterns and provide guidance on potential issues.
   - Manual Testing: Actively test the deserialization logic within the application by tracing the flow of serialized data. Monitor the deserialization process and ensure that proper validation, type checking, and exception handling are implemented.

Recommendations to mitigate insecure deserialization vulnerabilities:

1. Input Validation: Implement strong input validation and filtering mechanisms to ensure that serialized data is properly validated and sanitized before deserialization.

2. Use Safe Deserialization Libraries: Employ secure deserialization libraries or frameworks that provide built-in protections against common deserialization attacks. These libraries often include features like type checking, depth limiting, and integrity checks.

3. Principle of Least Privilege: Ensure that the deserialization process has minimal access rights and operates with the least privilege necessary to perform its intended functions.

4. Update and Patch: Keep all deserialization libraries and frameworks up to date with the latest security patches to mitigate known vulnerabilities.

5. Monitor and Log: Implement robust logging and monitoring mechanisms to detect any suspicious or abnormal deserialization activities. Monitor for unexpected exceptions, errors, or excessive deserialization requests.

6. Secure Configuration: Disable deserialization in components or modules that do not require it. If deserialization is necessary, configure it to use secure settings and avoid unnecessary or risky deserialization points.

7. Security Testing: Regularly perform security testing, including both black box and white box techniques, to identify and address insecure deserialization vulnerabilities.

---

**`What is SQL Injection, Types of SQL Injection and Recommendations ? What is stored procedure are they secure against SQL Injection ?`**

QL Injection is a web application vulnerability that occurs when an attacker can manipulate user-supplied input to execute arbitrary SQL commands on a database. It arises when input data is not properly validated or sanitized before being used in SQL queries. SQL Injection can lead to unauthorized data access, data manipulation, and in some cases, complete compromise of the underlying database.

Types of SQL Injection:

    Classic SQL Injection: The attacker injects malicious SQL statements into user input fields, such as login forms or search fields. These statements are then executed by the application's database, potentially giving the attacker unauthorized access or control over the database.

    Blind SQL Injection: In this type, the attacker doesn't directly see the database output. However, they can exploit boolean-based or time-based techniques to infer information from the application's response, allowing them to extract sensitive data or modify the database indirectly.

    Time-Based SQL Injection: The attacker manipulates the SQL query in a way that causes a delay in the response. By analyzing the application's response time, the attacker can extract information from the database.

    Union-based SQL Injection: The attacker uses the UNION operator to combine the result sets of multiple queries. By injecting malicious UNION statements, the attacker can extract data from other database tables.

Recommendations to mitigate SQL Injection vulnerabilities:

    Use Parameterized Queries or Prepared Statements: Instead of concatenating user input directly into SQL statements, use parameterized queries or prepared statements, which separate the SQL code from the user-supplied data. This helps prevent malicious input from being interpreted as SQL commands.

    Input Validation and Sanitization: Implement strict input validation and sanitization techniques to filter out or escape special characters that could be used for SQL injection attacks. Apply input validation on both client-side and server-side to provide an additional layer of protection.

    Principle of Least Privilege: Ensure that the database user account used by the application has limited permissions and access rights, granting only the necessary privileges to perform its intended functions. Avoid using privileged accounts for normal application operations.

    Database Firewall: Employ a database firewall or intrusion detection system (IDS) that can detect and block SQL injection attempts. These tools analyze database traffic and can identify and prevent suspicious SQL statements from being executed.

    Least Privileged Database Accounts: Create separate database accounts with the least privileges required for different application components or modules. This helps minimize the potential impact of a successful SQL injection attack.

    Regular Security Updates and Patching: Keep the database software and frameworks up to date with the latest security patches to mitigate known vulnerabilities that can be exploited by attackers.

Regarding stored procedures, they can help mitigate SQL injection vulnerabilities to some extent. By using parameterized stored procedures, you separate the SQL logic from user input, reducing the risk of injection attacks. However, it is important to note that stored procedures are not a foolproof solution and can still be vulnerable if they are poorly designed or implemented.

---

**`What is XSS ? Types of XSS ? Difference between DOM Based XSS & Reflected XSS ? What is DOM in DOM Based XSS ? Recommendations for XSS ?`**

XSS (Cross-Site Scripting) is a web application vulnerability that allows attackers to inject and execute malicious scripts in a victim's browser. It occurs when user-supplied input is improperly validated or sanitized and then displayed on a website without proper encoding or escaping.

Types of XSS:

    Reflected XSS: In this type, the malicious script is embedded in a URL or a form input, which is then reflected back to the user in the website's response. The victim's browser executes the script, resulting in potential data theft, session hijacking, or unauthorized actions.

    Stored XSS: In stored XSS, the malicious script is permanently stored on the target server (e.g., in a database, comment section, or user profile). When other users view the page, the script is served from the server and executed in their browsers, leading to the same risks as reflected XSS.

    DOM (Document Object Model) Based XSS: DOM-based XSS occurs when the vulnerability is exploited at the client-side, in the browser's Document Object Model. The attack takes place by manipulating the DOM tree, which represents the webpage's structure and content. The malicious script is injected and executed within the victim's browser, often resulting from insecure JavaScript coding practices.

Difference between DOM-Based XSS and Reflected XSS:

Reflected XSS and DOM-Based XSS differ in the way the malicious script is injected and executed:

    Reflected XSS: The attack payload is injected into the server's response and then reflected back to the user's browser. The script is executed in the victim's browser as part of the response rendering process.

    DOM-Based XSS: The attack payload is injected into the client-side script directly or through manipulation of the DOM tree. The malicious script is then executed within the victim's browser as part of the client-side code execution.

Recommendations to mitigate XSS vulnerabilities:

    Input Validation and Output Encoding: Implement strict input validation to ensure that user-supplied data does not contain malicious scripts. Additionally, properly encode and sanitize all output that is rendered on web pages to prevent script execution.

    Content Security Policy (CSP): Utilize Content Security Policy to restrict the sources from which the website can load scripts, preventing unauthorized script execution.

    Use Safe APIs and Libraries: Make use of secure and well-tested libraries or frameworks that provide built-in protection against XSS attacks, such as template engines that automatically encode output or DOM manipulation libraries that mitigate injection risks.

    Proper Contextual Output Encoding: Understand the context in which the user-supplied data is being displayed (HTML, attribute, JavaScript, etc.) and apply the appropriate encoding techniques to prevent script execution.

    Cookie Security: Set the "HttpOnly" flag for cookies to prevent access by client-side scripts and mitigate the risk of session theft through XSS attacks.

    Regular Security Updates: Keep all web application components, including frameworks, libraries, and plugins, up to date with the latest security patches to address known vulnerabilities.

    Security Headers: Utilize security headers, such as X-XSS-Protection and X-Content-Type-Options, to provide additional security measures and instruct the browser to handle content in a secure manner.

    Secure Coding Practices: Follow secure coding practices, such as input validation, parameterized queries, and avoiding the use of unsafe functions like "eval()" or "innerHTML" that can introduce XSS vulnerabilities.

    Security Testing: Regularly perform security testing, including both manual and automated scanning, to identify and address any XSS vulnerabilities.

---

**`Difference Between Ordinary XSS and DOM Based XSS:`**

The main difference between ordinary XSS (also known as Reflected or Stored XSS) and DOM-based XSS lies in the location where the vulnerability is exploited and the way the malicious script is executed.

    Exploitation Location:
        Ordinary XSS: In ordinary XSS, the vulnerability is exploited on the server-side. The attacker injects a malicious script into user input, such as URL parameters or form fields, which are then stored on the server and reflected back to other users. The script is executed when the server generates the response and sends it to the victim's browser.
        DOM-based XSS: In DOM-based XSS, the vulnerability is exploited on the client-side, specifically within the Document Object Model (DOM) of the victim's browser. The attacker injects a script that manipulates the DOM tree or modifies the client-side JavaScript code directly, leading to the execution of the malicious script within the victim's browser.

    Execution Mechanism:
        Ordinary XSS: In ordinary XSS, the malicious script is executed as part of the web page rendering process. The script is embedded in the server's response and interpreted by the victim's browser upon rendering the page. The script can access and modify the DOM, make requests to other domains, steal sensitive data, or perform other malicious actions.
        DOM-based XSS: In DOM-based XSS, the execution of the malicious script occurs within the victim's browser's DOM environment. The script directly interacts with the DOM tree, manipulating its structure or triggering specific events. The manipulated DOM tree may then cause unintended behavior or the execution of other scripts, potentially leading to unauthorized actions or data theft.

    Mitigation Approach:
        Ordinary XSS: Mitigating ordinary XSS typically involves input validation and output encoding/sanitization on the server-side. The goal is to ensure that user-supplied input is properly validated, and any output rendered on web pages is appropriately encoded to prevent script execution.
        DOM-based XSS: Mitigating DOM-based XSS requires a client-side approach, as the vulnerability is exploited within the victim's browser. Developers need to ensure secure coding practices, proper context-aware output encoding, and protection against DOM manipulation vulnerabilities. Tools like Content Security Policy (CSP) can also be used to restrict script execution sources.

Both ordinary XSS and DOM-based XSS can have severe security implications. It is crucial to employ comprehensive security measures, including input validation, output encoding, secure coding practices, and regular security testing, to mitigate the risk of both types of XSS attacks.

---

**`What is CORS ? How to Exploit Missconfigured CORS? they may ask you about the headers like “Origin”, “Access Control Allow Origin” etc.`**

CORS (Cross-Origin Resource Sharing) is a mechanism that allows web browsers to enforce security policies on cross-origin requests. It is a crucial security feature implemented by modern web browsers to protect against cross-origin attacks.

CORS defines a set of HTTP headers that enable controlled access to resources on a different origin (domain, protocol, or port). The relevant headers include:

    Origin: This header is sent by the browser to indicate the origin of the requesting page. It specifies the domain from which the request originates.

    Access-Control-Allow-Origin: This header is sent by the server in response to a CORS request. It specifies which origins are allowed to access the requested resource. It can have the value of "*", indicating that any origin is allowed, or specific origins can be listed.

    Access-Control-Allow-Methods: This header is sent by the server to specify the HTTP methods (e.g., GET, POST, PUT) allowed for the CORS request.

    Access-Control-Allow-Headers: This header is sent by the server to specify the allowed headers for the CORS request.

Exploiting Misconfigured CORS:

Misconfigured CORS can lead to security vulnerabilities, such as cross-site scripting (XSS), cross-site request forgery (CSRF), or leaking sensitive information. Here are some common ways to exploit misconfigured CORS:

    Cross-Domain Data Theft: If the server allows all origins ("*") in the Access-Control-Allow-Origin header and does not implement proper authentication or authorization checks, an attacker can use a malicious website to make requests to the server and access sensitive data in the responses.

    Cross-Site Scripting (XSS): If the server responds with overly permissive Access-Control-Allow-Origin headers, an attacker can inject malicious scripts into a vulnerable website and steal user information or perform unauthorized actions.

    Cross-Site Request Forgery (CSRF): Misconfigured CORS headers can potentially enable CSRF attacks by allowing cross-origin requests to perform actions on behalf of a user without their knowledge or consent.

To mitigate the risks associated with CORS misconfigurations, consider the following best practices:

    Restrict Origins: Set the Access-Control-Allow-Origin header to specific origins that are allowed to access the resource. Avoid using "*" unless it is absolutely necessary.

    Implement Proper Authentication and Authorization: Implement proper authentication and authorization checks on the server-side to ensure that only authorized users can access sensitive resources.

    Validate and Sanitize Inputs: Validate and sanitize all user inputs on the server-side to prevent injection attacks or other security vulnerabilities.

    Use CSRF Protection: Implement CSRF protection mechanisms, such as anti-CSRF tokens, to mitigate the risk of CSRF attacks.

    Leverage Appropriate HTTP Methods and Headers: Use the Access-Control-Allow-Methods and Access-Control-Allow-Headers headers to restrict the allowed HTTP methods and headers for CORS requests.

    Regular Security Audits: Perform regular security audits, including testing for CORS vulnerabilities, to identify and address any misconfigurations or security issues.

---

**`What is SSRF ? What can be accomplished by exploiting SSRF ? Recommendations ?`**

SSRF (Server-Side Request Forgery) is a web vulnerability that allows an attacker to make requests from the server to other internal or external resources. It occurs when an application accepts user-supplied input and uses it to make requests to arbitrary URLs. Exploiting SSRF can have severe consequences, including unauthorized access to internal systems, information disclosure, and potentially remote code execution.

Accomplishments through SSRF Exploitation:

    Network Scanning and Port Scanning: Attackers can abuse SSRF to scan internal networks or ports, identifying vulnerable systems and services that can be further targeted.

    Accessing Internal Resources: By exploiting SSRF, attackers can make requests to internal resources, such as administrative panels, databases, or private APIs, which are typically not meant to be accessible from the public internet.

    Exploiting Internal Services: SSRF can be used to target internal services or applications that trust requests from other internal components. By making malicious requests to these services, an attacker may gain unauthorized access or manipulate sensitive data.

    Remote Code Execution (RCE): In some cases, SSRF can be escalated to achieve RCE by making requests to URLs that execute server-side code, such as file inclusion vulnerabilities or server-side template injection.

Recommendations to mitigate SSRF vulnerabilities:

    Input Validation and Whitelisting: Implement strict input validation and whitelist the allowed protocols, IP addresses, and hostnames. Validate and sanitize user-supplied input to prevent SSRF attacks.

    Use of Safe APIs and Libraries: Utilize safe APIs and libraries that provide built-in protection against SSRF vulnerabilities. For example, use libraries that allow configuring a whitelist of allowed hosts or provide methods to restrict requests to specific resources.

    Restrict Network Access: Restrict network access from the server-side to only necessary resources and services. Employ proper network segmentation and firewall rules to limit internal system exposure.

    Use Least Privilege: Ensure that the server's executing environment has the least privilege necessary to perform its intended functions. Avoid using privileged accounts or roles for making requests to external resources.

    Filter User-Provided URLs: Implement strong URL filtering mechanisms to ensure that user-supplied URLs are safe and do not contain internal or malicious addresses.

    Protect Internal Endpoints: Apply proper authentication, authorization, and access controls to internal resources. These measures will help prevent unauthorized access even if SSRF occurs.

    Security Testing and Auditing: Regularly perform security testing, including SSRF vulnerability scanning and penetration testing, to identify and address any SSRF vulnerabilities. Additionally, conduct code reviews and security audits to catch potential SSRF-prone code patterns.

    ---

**`What is CSRF ? Recommendations ? What is Double Submit Cookie in CSRF ? is it possible to exploit CSRF in JSON request if yes then how ?`**

CSRF (Cross-Site Request Forgery) is a web vulnerability that allows an attacker to trick a victim into unknowingly executing unwanted actions on a web application in which the victim is authenticated. It occurs when an application does not properly validate or enforce the origin of a request, allowing malicious actors to forge requests on behalf of the victim.

Recommendations to mitigate CSRF vulnerabilities:

    Implement CSRF Tokens: Include CSRF tokens in forms or as headers with each request to validate the origin and authenticity of the request. The server can verify the token to ensure that the request is legitimate and originated from the expected source.

    Same-Site Cookies: Set the SameSite attribute of cookies to "Strict" or "Lax" to restrict their transmission to same-site requests only. This prevents CSRF attacks where the attacker's website attempts to make requests on behalf of the user.

    Anti-CSRF Headers: Include anti-CSRF headers, such as "X-CSRF-Token" or "X-Requested-With", in requests to further mitigate CSRF attacks. These headers can be checked by the server to validate the request's origin.

    Origin Checking: Verify the "Origin" or "Referer" header of incoming requests on the server-side to ensure that requests are originating from the expected domain. However, note that the "Referer" header can be spoofed or omitted, so it should be used cautiously.

    Strict CORS Policies: Implement strict CORS (Cross-Origin Resource Sharing) policies to restrict cross-origin requests. Utilize appropriate Access-Control-Allow-Origin headers to specify allowed origins and prevent unauthorized requests.

    User Interaction for Sensitive Actions: Require user interaction, such as confirmation prompts or CAPTCHAs, for sensitive actions that can have significant consequences. This reduces the risk of automated CSRF attacks.

Double Submit Cookie in CSRF:

Double Submit Cookie is a technique used to mitigate CSRF attacks. It involves sending a cookie value that matches a token embedded in the request payload or as a header. The server compares the cookie value with the token to validate the request's authenticity. Since the token is included in both the cookie and request payload, the attacker cannot forge a request successfully without having access to the victim's cookies.

CSRF in JSON Requests:

Yes, CSRF attacks can also target JSON requests. While traditional CSRF attacks typically exploit HTML forms, JSON requests are not immune to CSRF vulnerabilities. Attackers can forge JSON requests by abusing other mechanisms, such as XMLHttpRequest or Fetch API, to send unauthorized requests to the target application.

To protect against CSRF in JSON requests, the same recommendations apply:

    Implement CSRF tokens for JSON requests.
    Validate the Origin or Referer header of incoming requests.
    Utilize anti-CSRF headers in JSON requests.
    Apply strict CORS policies to restrict cross-origin requests.
    Require user interaction for sensitive JSON actions.

    ---

**`What is IDOR ? Diffrence between IDOR and Missing Function Level access control ? Recommendations ?`**

IDOR (Insecure Direct Object References) is a web application vulnerability that occurs when an application exposes internal object references, such as database records or file paths, to unauthenticated or unauthorized users. Attackers can exploit IDOR vulnerabilities to access, modify, or delete sensitive data or resources without proper authorization.

Difference between IDOR and Missing Function Level Access Control:

IDOR and Missing Function Level Access Control are both vulnerabilities related to improper access controls, but they differ in their nature:

1. IDOR: IDOR specifically refers to the exposure of direct object references. It occurs when an attacker can manipulate parameters or values in requests to access or modify sensitive resources directly, bypassing intended access controls. For example, an attacker may change a numeric identifier in a URL or request parameter to access someone else's private data.

2. Missing Function Level Access Control: Missing Function Level Access Control, on the other hand, is a broader vulnerability that occurs when an application does not properly enforce access controls on certain functionality or actions. It means that the application fails to check if a user has the necessary privileges or permissions before performing a particular function. This can allow attackers to abuse or manipulate functionalities that should be restricted to specific users or roles.

Recommendations to mitigate IDOR and Missing Function Level Access Control vulnerabilities:

1. Implement Proper Access Controls: Ensure that your application has appropriate access controls in place for all sensitive resources and functionalities. Apply role-based access controls (RBAC) and enforce authorization checks at both the front-end and back-end.

2. Validate User Permissions: Validate user permissions on the server-side before performing any critical actions or accessing sensitive data. Avoid relying solely on client-side controls or hidden fields to prevent unauthorized access.

3. Use Indirect Object References: Avoid exposing direct object references in URLs, parameters, or hidden fields. Instead, use indirect references or unique identifiers that are not easily guessable or tampered with.

4. Authenticate and Authorize: Implement robust authentication mechanisms to verify user identities and associate them with appropriate authorization roles or access levels. Ensure that all authenticated actions are properly authorized.

5. Security by Design: Incorporate security into the development lifecycle by following secure coding practices, performing security reviews, and conducting regular vulnerability assessments and penetration testing.

6. Least Privilege Principle: Apply the principle of least privilege, granting users only the necessary privileges and access rights required to perform their intended tasks. Limit access to sensitive resources to authorized personnel or roles.

7. Logging and Monitoring: Implement logging and monitoring mechanisms to detect any suspicious activities, unauthorized access attempts, or unexpected behavior. Monitor access logs and regularly review them for potential security incidents.

By implementing these recommendations, you can significantly reduce the risk of IDOR and Missing Function Level Access Control vulnerabilities and enhance the overall security of your web applications.

---

**`What is session fixation attack ? Recommendations ?`**

Session fixation is a web attack where an attacker establishes a valid session with a target application and then tricks a victim into using that session. The attack typically involves forcing the victim to use a known session identifier, which the attacker can later exploit to gain unauthorized access.

Here's a step-by-step overview of a session fixation attack:

1. Attacker obtains a session identifier: The attacker initiates a session with the target application and obtains a valid session identifier.

2. Attacker shares the session identifier: The attacker tricks the victim into using the session identifier. This can be achieved through various means, such as sending a link with the session identifier or manipulating the victim's browser to use the attacker's session.

3. Victim unknowingly uses the shared session identifier: The victim clicks the provided link or unknowingly uses the shared session identifier to authenticate themselves with the target application.

4. Attacker exploits the session: Since the attacker knows the session identifier, they can now access the victim's session and perform unauthorized actions on their behalf.

Recommendations to mitigate session fixation attacks:

1. Use Strong Session Management Techniques: Implement robust session management practices, including the generation of random, unpredictable session identifiers. Avoid using easily guessable session IDs or identifiers that can be manipulated.

2. Assign New Session Identifiers: Whenever a user authenticates or performs a privileged action, assign a new session identifier. This practice helps prevent session fixation by rendering any shared session identifiers ineffective.

3. Implement Session Expiration: Set appropriate session expiration policies. This ensures that sessions expire after a reasonable period of inactivity, reducing the window of opportunity for attackers to exploit session fixation.

4. Secure Session Transmission: Ensure that session identifiers are transmitted securely over HTTPS. This helps protect against interception and eavesdropping attempts.

5. Regenerate Session Identifiers: Whenever a user's privilege level changes (e.g., after login or authentication), regenerate the session identifier to mitigate the risk of session fixation.

6. User Education: Educate users about the risks of clicking on unfamiliar or untrusted links and the importance of verifying the security of the URLs they visit.

7. Secure Coding Practices: Adhere to secure coding practices, such as input validation, output encoding, and proper handling of session identifiers. Avoid exposing session identifiers in URLs or other easily accessible locations.

8. Regular Security Audits: Conduct regular security audits and vulnerability assessments to identify and address any session management vulnerabilities or weaknesses.

---

**`Common flags on a cookie ? what is httponly flag ? what is the diffrence between httponly flag and secure httponlyflag`**

**`What is the difference between SSL and TLS ? Explain the process of SSL/TLS hamdshake ?`**

**`What is Content Security Policy (CSP) ? and common use cases of CSP ?`**

**`what is the difference between Asymmetric and symmetric encryption ?`**

**`What is the difference between encryption,encoding and Hashing ?`**

**`What is Server SIde template Injection ?`**

**`What is Http Parameter Pollution Attack ?`**

**`What is CRLF Injection ?`**

**`What is the Difference between OS command Injection and Remote Code execution ?`**

**`How you can bypass restricted file uploads ?`**

**`What is HSTS Header ?`**

**`What you will Look in Manifest.xml file in Security Testing of Android Apps ?`**

**`What is SSL Pinning in Android & how it can be bypassed?`**

**`What is DNS Zone Transfer Attack ?`**

**`What is SMTP Relay attack ?`**

**`What is SMB Relay ?`**

**`What is Pivoting ?`**

**`What is the difference Between Telnet & SSH ?`**

**`What is Pass The Hash Attack ?`**

**`What is HTTP Response splitting attack ?`**

**`What is Web cache deception attack ?`**

**`What is web cache poisioning attack ?`**

**`What is HTP Request Smuggling ( HTTP Dsync ) attack ?`**

**`What is HTP Request Smuggling ( HTTP Dsync ) attack ?`**

**`What is Openid & SSO in Web applications ?`**

**`What is SAML ? attacks & Recommandations ?`**

**`what Oauth & how to exploit a misconfigured Oauth ?`**

---

**And the last but not least**

**`Do you have any question ?`**
“This part is depend on you”, but I always ask a question in my interviews “Do you have any suggestions for me on the basis of this interview, and what are the things I need to work on for the next interviews”.

