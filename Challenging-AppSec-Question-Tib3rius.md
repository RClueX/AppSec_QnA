### `Challenging Web AppSec interview questions` 

---

### Created By [Tib3rius](https://github.com/Tib3rius)

---


**Question 1: Describe how HTTP Parameter Pollution could be used to bypass a Web Application Firewall.**

Some servers will concatenate parameter values if two or more identical parameters exist in requests, though often with a separator (e.g. a comma). For certain payloads, WAF detection can sometimes be bypassed if the payload can be split across multiple parameters.

---

**Question 2: What does the "unsafe-inline" value allow for if used in the script-src directive of a CSP?**

---

**Question 3: What is DOM Clobbering and how can it be used to bypass (some) HTML sanitizers, resulting in XSS?**

DOM Clobbering is a way to manipulate the DOM using only HTML elements (i.e. no JavaScript). By using the id or name attribute of some elements, it is possible to create global variables in the DOM. This can lead to XSS in some cases.

I created a dynamic cheatsheet where you can see how DOM Clobbering works: https://tib3rius.com/dom/ (works best in Chrome)!

---

**Question 4: What is the purpose of the Sec-WebSocket-Key header?**

---

**Question 5: How does the TE.TE variant of HTTP Request Smuggling work?**

Nobody had any excuse for getting this one wrong, because I'd released a video which covered it in depth 4 days prior! https://lnkd.in/eMDqrUbU

The TE.TE variant has two or more servers which always use the Transfer-Encoding header over the Content-Length header if both are present, which usually makes Request Smuggling impossible. However, by manipulating the Transfer-Encoding header, it is possible to cause one of the servers to not recognize it. This server will use the Content-Length header instead, allowing the Request Smuggling attack to work.

There are countless ways to manipulate the Transfer-Encoding header. Common ones are including whitespace before the colon, capitalization, or modifying the value "chunked" in the header itself.

---

**Question 6: Describe 3 payloads you could use to identify a server-side template engine by causing an error message.**

---

**Question 7: What is the Same-Origin Policy (SOP) and how does it work?**

The Same-Origin Policy is a security mechanism browsers use to prevent a variety of cross-origin attacks. The basic principle is that client-side app code can only read data from a specific URL if the URL has the same origin as the current app. Two URLs have the same origin if they share the same protocol, host, and port.

Note that reading and embedding data from URLs are treated differently, allowing applications to embed things like scripts, videos, images, etc. without actually being able to access the raw bytes of each.

---

**Question 8: In the context of web apps, what is Business Logic and how does testing for Business Logic vulnerabilities differ compared to (for example) XSS, SQLi, etc.**

---

**Question 9: How does Boolean *Error* Inferential (Blind) SQL Injection work?**

This one confused a lot of people. Boolean Inferential (or Blind) and Error-based SQL Injection are two different things, but neither were what I asked about. I very specifically wanted the Error variant of Boolean Inferential injection.

This is a variant where injecting "AND 1=1" and "AND 1=2" (for example) will return the same response! The trick is to purposefully cause a database error when a condition we want to test is true, and hope that error propagates back to the response somehow (e.g. a 500 Internal Server error).

Many ways to do this, but most use a CASE expression and some divide by zero if the condition is true. For example: AND 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)

---

**Question 10: What are JWKs and JKUs and how does their usage differ in JWTs?**

---

**Question 11: Name 5 (or more) types of Cross-Site Scripting.**

This was quite controversial and I was generally pretty lenient on what constituted a "type". The 5 I had in mind while writing the question were: Reflected, Stored, DOM-based, CSTI, and Server-Side.

Other types suggested by people were: Self, XST, Universal, Blind, Mutation

---

**Question 12: Describe IDOR and explain how mitigating it is different from other access control vulnerabilities.**

---

**Question 13: What are the differences between Base64 and Base64URL encoding?**

Ok, this was a pretty easy one! In Base64URL encoding, a "-" is used instead of a "+", and a "_" instead of a "/". Padding with = is also optional, and is usually omitted. This is to provide more compatibility if the value needs to be used in a URL.

Did you know that padding is actually not required at all for decoding, even in regular Base64? This is because we can figure out how many bytes are left to decode based on the number of remaining Base64 characters:
```
2 characters = 1 more byte
3 characters = 2 more bytes
````

---

**Question 14: Describe how HTTP Parameter Pollution could be used to bypass a Web Application Firewall.**

---

**Question 15: What two criteria must be met to exploit Session Fixation?**

A lot of confusion over this one. Session Fixation is not the same thing as Session Hijacking, but rather a type of Session Hijacking attack. The two criteria are:

1. Attacker must be able to forcibly set a (syntactically valid but otherwise inactive) session token in the victim's browser (e.g. using XSS / CRLF injection).
2. Once the victim authenticates, the application uses the session token already present and does not set a new one.

---

**Question 8:What is DOM Clobbering and how can it be used to bypass (some) HTML sanitizers, resulting in XSS?**

---

**Question 1: What is the difference between Web Cache Deception and Web Cache Poisoning?**

Web Cache Deception involves finding some dynamic page which you can access via a URL a web cache will automatically cache (e.g. if /transactions can be accessed at /transactions.jpg). If an attacker can trick a victim into visiting the cacheable URL, they can then load the same URL and retrieve the victim's information from the cache.

Web Cache Poisoning involves finding an input which results in some exploitable change in the response, but doesn't form part of the cache key for the request. When an attacker sends their payload, the exploited response will be cached and then delivered to anyone who accesses the page.

---

**Question 6:What is the Same-Origin Policy (SOP) and how does it work?**

---

**Question 5:How does Boolean *Error* Inferential (Blind) SQL Injection work?**

---

**Question 3:What are the differences between Base64 and Base64URL encoding?**

---

**Question 2:What two criteria must be met to exploit Session Fixation?**

---
---





