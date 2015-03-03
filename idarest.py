from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from SocketServer import ThreadingMixIn
import re
import threading
import cgi
import urlparse
import json

try:
    import idaapi
    import idautils
    import idc
except:
    pass

PORT = 8899

API_PREFIX = '/ida/api/v1.0'

class HTTPRequestError(BaseException):
    def __init__(self, msg, code):
        self.msg = msg
        self.code = code


class HTTPRequestHandler(BaseHTTPRequestHandler):
    routes = []

    @staticmethod
    def build_route_pattern(route):
        return re.compile("^{0}$".format(route))

    @staticmethod
    def route(route_str):
        def decorator(f):
            route_path = API_PREFIX + route_str
            route_pattern = HTTPRequestHandler.build_route_pattern(route_path)
            HTTPRequestHandler.routes.append((route_pattern, f))
            return f
        return decorator

    def get_route_match(self, path):
        for route_pattern, view_function in self.routes:
            m = route_pattern.match(path)
            if m:
                return view_function
        return None

    def _serve_route(self, args):
        path = urlparse.urlparse(self.path).path
        route_match = self.get_route_match(path)
        if route_match:
            view_function = route_match
            return view_function(self, args)
        else:
            raise HTTPRequestError('Route "{0}" has not been registered'.format(path), 404)

    def _serve(self, args):
        try:
            response = self._serve_route(args)
        except HTTPRequestError as e:
            response = {'code': e.code, 'msg' : e.msg}
        except ValueError as e:
            return {'code': 400, 'msg': 'ValueError : ' + str(e)}
        except KeyError as e:
            return {'code': 400, 'msg': 'KeyError : ' + str(e)}

        jsonp_callback = self._extract_callback()
        if jsonp_callback:
            content_type = 'application/javascript'
            response_fmt = jsonp_callback + '({0})'
        else:
            content_type = 'application/json'
            response_fmt = '{0}'

        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.end_headers()
        if response:
            response = json.dumps(response)
            self.wfile.write(response_fmt.format(response))

    def _extract_post_map(self):
        content_type,_t = cgi.parse_header(self.headers.getheader('content-type'))
        if content_type != 'application/json':
            raise HTTPRequestError('Bad content-type, use application/json', 403)
        length = int(self.headers.getheader('content-length'))
        return json.loads(self.rfile.read(length))

    def _extract_query_map(self):
        query = urlparse.urlparse(self.path).query
        qd = urlparse.parse_qs(query)
        args = {}
        for k,v in qd.iteritems():
            if len(v) != 1:
                raise ValueError("Bad query args")
            args[k.lower()] = v[0]
        return args

    def _extract_callback(self):
        try:
            args = self._extract_query_map()
            return args['callback']
        except KeyError:
            return ''
        except ValueError:
            return ''

    def do_POST(self):
        try:
            args = self._extract_post_map() 
        except TypeError:
            args = '{}'
        except ValueError:
            args = '{}'
        except HTTPRequestError as e:
            self.send_error(e.code, e.msg)
            return

        self._serve(args)

    def do_GET(self):
        try:
            args = self._extract_query_map() 
        except TypeError:
            args = '{}'
        except ValueError:
            args = '{}'
        self._serve(args)


class IDARequestHandler(HTTPRequestHandler):
    @staticmethod
    def _hex(v):
        return hex(v).rstrip('L')

    @staticmethod
    def _ea(x):
        try:
            return int(x)
        except ValueError:
            return int(x, 16)

    # XXX IDA Color is BBGGRR, we should accept and convert from RGB
    @staticmethod
    def _color(x):
        return IDARequestHandler._ea(x)

    @HTTPRequestHandler.route('/cursor/?')
    def cursor(self, args):
        if 'ea' in args:
            ea = self._ea(args['ea'])
            def f():
                #tform = idaapi.find_tform(args['window'])
                #if tform:
                #    idaapi.switchto_tform(tform, 1)
                idaapi.jumpto(int(args['ea'], 16))
            idaapi.execute_sync(f, idaapi.MFF_FAST)
            return { 'code' : 200, 'msg' : 'OK' }
        else:
            return { 'ea' : self._hex(idaapi.get_screen_ea()) }

    @HTTPRequestHandler.route('/names/?')
    def names(self, args):
        m = {'names' : []}
        for n in idautils.Names():
            m['names'].append([self._hex(n[0]), n[1]])
        return m

    @HTTPRequestHandler.route('/color/?')
    def color(self, args):
        ea = self._ea(args['ea'])
        if 'color' in args:
            color = self._color(args['color'])
            def f():
                idc.SetColor(ea, idc.CIC_ITEM, color)
                idc.Refresh()
            idaapi.execute_sync(f, idaapi.MFF_WRITE)
            return {'code': 200, 'msg': 'OK'}
        else:
            return {'color' : str(GetColor(ea, idc.CIC_ITEM))}
        

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True


class Worker(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.httpd = ThreadedHTTPServer(('0.0.0.0', PORT), IDARequestHandler)

    def run(self):
        self.httpd.serve_forever()

    def stop(self):
        self.httpd.shutdown()

#worker = Worker()
#worker.start()
#httpd = ThreadedHTTPServer(('0.0.0.0', PORT), IDARequestHandler)
#httpd.serve_forever()

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = ""
    help = "IDA Rest API for basic RE tool interoperability"
    wanted_name = "IDA Rest API"
    wanted_hotkey = "Alt-F8"

    def init(self):
        # XXX
        # Add menu items to start/stop service
        idaapi.msg("Initializing %s\n" % self.wanted_name)
        self.worker = Worker()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("Running %s\n" % self.wanted_name)
        # XXX
        # Ask for port to bind to
        self.worker.start()
        # XXX
        # Check arg
        # Update self.flag to PLUGIN_UNL

    def term(self):
        idaapi.msg("Terminating %s\n" % self.wanted_name)
        self.worker.stop()
        del self.worker

def PLUGIN_ENTRY():
    return myplugin_t()



