# Standalone MultiScan Tools for ZAP (Zed Attack Proxy)
MultiscanTools is a set of security testing tools for ZAP: it enhances XSS, form based SQLInjection and Path Traversal.

# Who are we?
We are students of MESW (Software Engineering Masters) at FEUP (Porto Engineering University).

This was developed for Software Validation, Verification & Testing lecture as our State of the Art final project.

As we had to do a presentation about Security Testing we decided it would be great to improve ZAP and cover some failures we've encountered, during our testing for presentation.

# What do we think about security testing
Living without access to information at any time, from anywhere, through multiple devices is, nowadays, becoming unimaginable. Despite, information security is, now, more important than the access to that information.   
Lately, with the emerging of personal computers, smart phones, there are a lot of applications for everything, starting from searching on internet, to social networking, shopping, banking and a lot of more online services.

One can now imagine that there is a lot of information saved in our devices, such as, photos, documents, emails, conversations, important numbers, and lots of other type of information.
This information, critical or not, has to maintain its confidentiality. How can one guarantee it without testing? Well, he can't.

At first glance, one could think manual testing would suffice, but, what if the application scales, we have to test manually a lot of things and repeat the tests a million times or, even worse, we forget to test something that is really important.
This is when automate security testing arise. 

Automating security tests gives one the chance to just click a button to run a set of tests, saving a lot of time and effort at medium-long term, allows one to not forget about testing some feature and, probably more relevant, leads people to work together on producing scanning rules.

Although, keep in mind, this does not prevent, at all, zero day attacks. Still, what can prevent this type of attacks? Probably nothing. 

Summing up, automating security testing gives one the chance to test their application for known attacks in order to try to prevent them from happening.

Our opinion is that this subject is becoming more and more popular as technology evolves leading to a demand of increased security at twice the pace. Hence, we believe one should invest in this kind of tests, whether as usage or improvement, as we did on enhancing an extension for ZAP. 

![](https://github.com/pedroo21/ZAP-Multi-Scan-Rules/blob/master/imgs/security.jpg?raw=true)

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
We also discovered a lot more, but for starters purpose we're defining just the basic things.

### ASCANRULES
Active scanning rules is accounted for dealing with tests that do something in runtime, meaning they're actively "injecting" something, like Cross-Site Scripting (XSS), SQL Injection, Carriage Return Line Feed (CRLF), Path Traversal, Remote file include, and so on.

### PSCANRULES
Passive scanning rules refers to a set of rules that test for bad configurations, such as, Password Autocomplete, missing ContentType, X-XSS-Protection Header, etc.

### QUICKSTART
This package is, just as the name says, for starting with relative ease. We recommend you to use this, since it will save you a lot of time.   
Enables you to enter the website for testing, and executes all scans available.

![](https://github.com/pedroo21/ZAP-Multi-Scan-Rules/blob/master/imgs/quickstart.png?raw=true)

# Getting started
In this section we're going to explain what we did to start develop an extension for ZAP, so you can have an idea of what you need to do.    

1. Download/Clone/Fork ZAP github source code [here](https://github.com/zaproxy/zaproxy)
2. Download/Clone/Fork ZAP-Extensions github source code [here](https://github.com/zaproxy/zap-extensions)
3. We used IntelliJ and we had to do a few configurations. We describe them below
4. As ZAP-Extensions project is not runnable and it's using Ant as a build framework you need to open Ant Build window. In IntelliJ simply click on `View > Tool Windows > Ant Build`.
A window should appear looking like [this](https://github.com/pedroo21/ZAP-Multi-Scan-Rules/blob/master/imgs/ant.png?raw=true)
5. We recommend you to run `compile` on Ant window
6. Then, for starters, we ran `deploy-quickstart`. After it's completion in returns a .zap extension file that, if you have the both projects in the same directory, will automatically place itself in ZAP addons folder. Otherwise you'll have to move the file to `zaproxy/src/plugin`
7. Run ZAP. If everything went successful you should see a window like the one below.
![](https://github.com/pedroo21/ZAP-Multi-Scan-Rules/blob/master/imgs/zap.png?raw=true)
8. Congratulations! Quickstart is now deployed and working. If you enter a website nothing will be scanned, since ascanrules are not deployed yet. Though you can type a website and click `Attack` 




