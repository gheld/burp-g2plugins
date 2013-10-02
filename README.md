burp-g2plugins
==============

## Requirements

1. [Install BurpSuite Pro](http://portswigger.net/burp/editions.html) (or any version where extensions are enabled)

2. [Add the Jython jar](http://www.burpextensions.com/tutorials/setting-up-the-pythonjython-environment-for-burp-suite/)

# G2DetermineSessionCookie
Determine which cookie(s) are required to maintain the session. It does this 
by making a series of requests: first establishing the request/response is 
predictable, next making sure cookies are required, then removing a cookie 
at a time until only the session cookies are left.

### Usage

1. Start burp and use the Extensions tab to add the G2DetermineSessionCookie python file

2. Login into an application

3. Using the Proxy History tab right click a request/response which is somewhat reliable (will not change too much if you request it over and over) but will change if you're not logged in.

4. Select G2DetermineSessionCookie


