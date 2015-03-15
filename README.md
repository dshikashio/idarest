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
Provide it in '''host:port''' format.  `127.0.0.1:8899` is the default setting.

Conventions
-----------
### Request Method
All APIs can be accessed with either GET or POST requests.  Arguments in GET
requests are passed as URL parameters.  Arguments in POST requests are passed as
JSON.

### Status and Errors
HTTP status returned will always be 200, 400, or 404.

404 occurs when requesting an unknown URL / API.

400 occurs for
* Bad POST arguments (must be application/json or malformed JSON)
* Bad QUERY arguments (specifying the same var multiple times)

200 will be returned for everything else, including *invalid* API argument
values.

### HTTP 200 Responses
All responses will be either JSON (`application/json`) or JSONP
(`application/javascript`) with JSON being the default format.  To have JSONP
returned, specify a URL parameter `callback` with both POST and GET requests.

All responses (errors and non-errors) have `code` and `msg` fields.  Responses
which have a 200 code also have a `data` field with additional information.

### Other conventions
* Numbers will be returned as hex formatted (0xABCD) strings.
* Input numbers must be provided in hex form
* `ea` is commonly used as address
* Color input is RRGGBB format in hex

API
---
### info : Meta information about the current IDB

**Example:**

    curl http://127.0.0.1:8899/ida/api/v1.0/info

### cursor : Get and set current disassembly window cursor position

**Example:**

    curl http://127.0.0.1:8899/ida/api/v1.0/cursor

    curl http://127.0.0.1:8899/ida/api/v1.0/cursor?ea=0x89ab

### segments : Get segment information

**Example:**

    curl http://127.0.0.1:8899/ida/api/v1.0/segments

    curl http://127.0.0.1:8899/ida/api/v1.0/segments?ea=0x89ab

### names : Get name list

**Example:**

    curl http://127.0.0.1:8899/ida/api/v1.0/names

### color : Get and set color information

**Example:**

    curl http://127.0.0.1:8899/ida/api/v1.0/color?ea=0x89ab

    curl http://127.0.0.1:8899/ida/api/v1.0/color?ea=0x89ab?color=FF0000

API To Do List
--------------
* query

Adding New APIs
---------------
### Registering handlers
* HTTPRequestHandler.prefn
* HTTPRequestHandler.postfn
* HTTPRequestHandler.route

### Decorators for parameter checking
* @check_ea
* @require_params

### Exceptions
* IDARequestError

