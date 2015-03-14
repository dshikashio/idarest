IDA Rest
========

A simple REST-like API for basic interoperability with IDA Pro.


Installing and Running
----------------------
Copy idarest.py to IDA Pro's plugin directory.

Use the Edit menu in IDA Pro to start and stop the plugin
* Edit -> Start IDARest
* Edit -> Stop IDARest

When starting the plugin you will be asked for the listening host and port.
Provide it in '''host:port''' format.


Conventions
-----------

errors - 200, 400, or 404
Get vs. Post
Json vs Jsonp
Response format (code, msg, data) in json
numbers are 0x hex strings


Adding New APIs
---------------
HTTPRequestHandler.prefn
HTTPRequestHandler.postfn
HTTPRequestHandler.route


API
---



