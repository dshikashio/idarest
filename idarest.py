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
            response = {'code': 400, 'msg': 'ValueError : ' + str(e)}
        except KeyError as e:
            response = {'code': 400, 'msg': 'KeyError : ' + str(e)}

        jsonp_callback = self._extract_callback()
        if jsonp_callback:
            content_type = 'application/javascript'
            response_fmt = jsonp_callback + '({0});'
        else:
            content_type = 'application/json'
            response_fmt = '{0}'

        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.end_headers()

        response = {
            'code' : 200,
            'msg'  : 'OK',
            'data' : response
        }
        response = json.dumps(response)
        self.wfile.write(response_fmt.format(response))

    def _extract_post_map(self):
        content_type,_t = cgi.parse_header(self.headers.getheader('content-type'))
        if content_type != 'application/json':
            raise HTTPRequestError(
                    'Bad content-type, use application/json',
                    400)
        length = int(self.headers.getheader('content-length'))
        try:
            return json.loads(self.rfile.read(length))
        except ValueError as e:
            raise HTTPRequestError(
                    'Bad or malformed json content',
                    400)

    def _extract_query_map(self):
        query = urlparse.urlparse(self.path).query
        qd = urlparse.parse_qs(query)
        args = {}
        for k,v in qd.iteritems():
            if len(v) != 1:
                raise HTTPRequestError(
                    "Query param specified multiple times : " + k,
                    400)
            args[k.lower()] = v[0]
        return args

    def _extract_callback(self):
        try:
            args = self._extract_query_map()
            return args['callback']
        except:
            return ''

    def do_POST(self):
        try:
            args = self._extract_post_map() 
        except TypeError as e:
            # thrown on no content, just continue on
            args = '{}'
        except HTTPRequestError as e:
            self.send_error(e.code, e.msg)
            return
        self._serve(args)

    def do_GET(self):
        try:
            args = self._extract_query_map() 
        except HTTPRequestError as e:
            self.send_error(e.code, e.msg)
            return
        self._serve(args)


"""
API handlers for IDA

"""
class IDARequestError(HTTPRequestError):
    pass

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
            return {}
        else:
            return { 'ea' : self._hex(idaapi.get_screen_ea()) }

    def _get_segment_info(self, s):
        return {
                'name' : idaapi.get_true_segm_name(s),
                'ida_name' : idaapi.get_segm_name(s),
                'start' : self._hex(s.startEA),
                'end' : self._hex(s.endEA),
                'size' : self._hex(s.size())
            }

    @HTTPRequestHandler.route('/segments/?')
    def segments(self, args):
        if 'ea' in args:
            ea = self._ea(args['ea'])
            s = idaapi.getseg(ea)
            if not s:
                raise  IDARequestError('Invalid address', 400)
            return {'segment': self._get_segment_info(s)}
        else:
            m = {'segments': []}
            for i in range(idaapi.get_segm_qty()):
                s = idaapi.getnseg(i)
                m['segments'].append(self._get_segment_info(s))
            return m

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
            return {}
        else:
            return {'color' : str(GetColor(ea, idc.CIC_ITEM))}

    # Add query handler
    # take an address, return as much known about is as possible
    
    # provide an info function - return all meta, general ida info
        

"""
Threaded HTTP Server and Worker

Use a worker thread to manage the server so that we can run inside of
IDA Pro without blocking execution.

"""
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True


class Worker(threading.Thread):
    def __init__(self, host='127.0.0.1', port=8899):
        threading.Thread.__init__(self)
        self.httpd = ThreadedHTTPServer((host, port), IDARequestHandler)

    def run(self):
        self.httpd.serve_forever()

    def stop(self):
        self.httpd.shutdown()

"""
IDA Pro Plugin Interface

Define an IDA Python plugin required class and function.
"""

MENU_PATH = 'Edit/Other'
class idarest_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = ""
    help = "IDA Rest API for basic RE tool interoperability"
    wanted_name = "IDA Rest API"
    wanted_hotkey = "Alt-7"

    def _add_menu(self, *args):
        idaapi.msg("Adding menu item\n")
        ctx = idaapi.add_menu_item(*args)
        if ctx is None:
            idaapi.msg("Add failed!\n")
            return False
        else:
            self.ctxs.append(ctx)
            return True

    def _add_menus(self):
        ret = []
        ret.append(
            self._add_menu(MENU_PATH, 'Stop IDARest', '', 1, self.stop, tuple()))
        ret.append(
            self._add_menu(MENU_PATH, 'Start IDARest', '', 1, self.start, tuple()))
        if False in ret:
            return idaapi.PLUGIN_SKIP
        else:
            return idaapi.PLUGIN_KEEP


    def init(self):
        idaapi.msg("Initializing %s\n" % self.wanted_name)
        self.ctxs = []
        self.worker = None
        self.port = 8899
        self.host = '127.0.0.1'
        ret = self._add_menus()
        idaapi.msg("Init done\n")
        return ret

    def _get_netinfo(self):
        info = idaapi.askstr(0,
                "{0}:{1}".format(self.host, self.port),
                "Enter IDA Rest Connection Info")
        if not info:
            raise ValueError("User canceled")
        host,port = info.split(':')
        port = int(port)
        return host,port

    def start(self, *args):
        idaapi.msg("Starting IDARest\n")
        if self.worker:
            idaapi.msg("Already running\n")
            return
        try:
            host,port = self._get_netinfo()
        except:
            host, port = "127.0.0.1", "8899"
            return

        try:
            self.worker = Worker(host,port)
        except Exception as e:
            idaapi.msg("Error starting worker : " + str(e) + "\n")
            return
        self.worker.start()
        self.host = host
        self.port = port
        idaapi.msg("Worker running\n")

    def stop(self, *args):
        idaapi.msg("Stopping IDARest\n")
        if self.worker:
            self.worker.stop()
            del self.worker
            self.worker = None

    def run(self, arg):
        pass

    def term(self):
        idaapi.msg("Terminating %s\n" % self.wanted_name)
        try:
            self.stop()
        except:
            pass
        for ctx in self.ctxs:
            idaapi.del_menu_item(ctx)

def PLUGIN_ENTRY():
    return idarest_plugin_t()

