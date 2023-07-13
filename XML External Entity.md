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

Define an external entity (&xxe;) whose value is the contents of /etc/passwd and uses the entity within the productId value
