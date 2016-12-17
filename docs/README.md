# Standalone MultiScan Tools for ZAP (Zed Attack Proxy)
MultiscanTools is a set of security testing tools for ZAP: it enhances XSS, form based SQLInjection and Path Traversal.

# Who are we?
We are students of MESW (Software Engineering Masters) at FEUP (Porto Engineering University).

This was developed for Software Validation, Verification & Testing lecture as our State of the Art final project.

As we had to do a presentation about Security Testing we decided it would be great to improve ZAP and cover some failures we've encountered, during our testing for presentation.

# What about ZAP

### ZAP

ZAP is developed by OWASP (Open Web Application Security Project). It is one of the most popular free and actively maintained, by many volunteers, Security Testing Tools.

It's meant to find security breaches in web applications while they're being developed and tested.

If you want to know more please visit their [website](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)

### ZAP-Extensions
Because ZAP is open source it implies there's a community around it that is eager to improve the tool, as we did. In order to separate concerns and projects they decided to create an extensions repository, which is called [ZAP-Extensions](https://github.com/zaproxy/zap-extensions).
Here, you can develop your features and improvements, so they can be used, later, on ZAP.

# What did we find when we started developing
ZAP is not a small tool, thus meaning it's code is also not small.
As we started diving into code we find that there's two main scan rules, ascanrules which stands for active scanning rules and pscanrules standing for passive scanning rules.

### ASCANRULES
Active scanning rules is accounted for dealing with tests that do something in runtime, meaning they're actively "injecting" something, like Cross-Site Scripting (XSS), SQL Injection, Carriage Return Line Feed (CRLF), Path Traversal, Remote file include, and so on.

### PSCANRULES
Passive scanning rules refers to a set of rules that test for bad configurations, such as, Password Autocomplete, missing ContentType, X-XSS-Protection Header, etc.