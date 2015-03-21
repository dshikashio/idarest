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

API_PREFIX = '/ida/api/v1.0'

class HTTPRequestError(BaseException):
    def __init__(self, msg, code):
        self.msg = msg
        self.code = code

class UnknownApiError(HTTPRequestError):
    pass

class HTTPRequestHandler(BaseHTTPRequestHandler):
    routes = {}
    prefns = {}
    postfns = {}

    @staticmethod
    def build_route_pattern(route):
        return re.compile("^{0}$".format(route))

    @staticmethod
    def route(route_str):
        def decorator(f):
            route_path = API_PREFIX + '/' + route_str + '/?'
            route_pattern = HTTPRequestHandler.build_route_pattern(route_path)
            HTTPRequestHandler.routes[route_str] = (route_pattern, f)
            return f
        return decorator

    @staticmethod
    def prefn(route_str):
        def decorator(f):
            HTTPRequestHandler.prefns.setdefault(route_str, []).append(f)
            return f
        return decorator

    @staticmethod
    def postfn(route_str):
        def decorator(f):
            HTTPRequestHandler.postfns.setdefault(route_str, []).append(f)
            return f
        return decorator

    def _get_route_match(self, path):
        for (key, (route_pattern,view_function)) in self.routes.items():
            m = route_pattern.match(path)
            if m:
                return key,view_function
        return None

    def _get_route_prefn(self, key):
        try:
            return self.prefns[key]
        except:
            return []

    def _get_route_postfn(self, key):
        try:
            return self.postfns[key]
        except:
            return []

    def _serve_route(self, args):
        path = urlparse.urlparse(self.path).path
        route_match = self._get_route_match(path)
        if route_match:
            key,view_function = route_match
            for prefn in self._get_route_prefn(key):
                args = prefn(self, args)
            results = view_function(self, args)
            for postfn in self._get_route_postfn(key):
                results = postfn(self, results)
            return results
        else:
            raise UnknownApiError('Route "{0}" has not been registered'.format(path), 404)

    def _serve(self, args):
        try:
            response = {
                'code' : 200,
                'msg'  : 'OK',
                'data' : self._serve_route(args)
            }
        except UnknownApiError as e:
            self.send_error(e.code, e.msg)
            return
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
def check_ea(f):
    def wrapper(self, args):
        if 'ea' in args:
            try:
                ea = int(args['ea'], 16)
            except ValueError:
                raise IDARequestError(
                        'ea parameter malformed - must be 0xABCD', 400)
            if ea > idc.MaxEA():
                raise IDARequestError(
                        'ea out of range - MaxEA is 0x%x' % idc.MaxEA(), 400)
            args['ea'] = ea
        return f(self, args)
    return wrapper

def check_color(f):
    def wrapper(self, args):
        if 'color' in args:
            color = args['color']
            try:
                color = color.lower().lstrip('#').rstrip('h')
                if color.startswith('0x'):
                    color = color[2:]
                # IDA Color is BBGGRR, we need to convert from RRGGBB
                color = color[-2:] + color[2:4] + color[:2]
                color = int(color, 16)
            except:
                raise IDARequestError(
                        'color parameter malformed - must be RRGGBB form', 400)
            args['color'] = color
        return f(self, args)
    return wrapper

def require_params(*params):
    def decorator(f):
        def wrapped(self, args):
            for x in params:
                if x not in args:
                    raise IDARequestError('missing parameter {0}'.format(x), 400)
            return f(self, args)
        return wrapped
    return decorator

class IDARequestError(HTTPRequestError):
    pass

class IDARequestHandler(HTTPRequestHandler):
    @staticmethod
    def _hex(v):
        return hex(v).rstrip('L')

    @HTTPRequestHandler.route('info')
    def info(self, args):
        # No args, Return everything we can meta-wise about the ida session
        # file crcs
        result = {
                'md5' : idc.GetInputMD5(),
                'idb_path' : idc.GetIdbPath(),
                'file_path' : idc.GetInputFilePath(),
                'ida_dir' : idc.GetIdaDirectory(),
                'min_ea' : self._hex(idc.MinEA()),
                'max_ea' : self._hexidc.MaxEA()),
                'segments' : self.segments({})['segments'],
                # idaapi.cvar.inf
                'procname' : idc.GetLongPrm(idc.INF_PROCNAME),
            }
        return result

    @HTTPRequestHandler.route('query')
    @check_ea
    def query(self, args):
        # multiple modes
        # with address return everything about that address
        # with name, return everything about that name
        return {}


    @HTTPRequestHandler.route('cursor')
    @check_ea
    def cursor(self, args):
        # XXX - Doesn't work
        #if 'window' in args:
        #    tform = idaapi.find_tform(args['window'])
        #    if tform:
        #        idaapi.switchto_tform(tform, 1)
        #    else:
        #        raise IDARequestError(
        #            'invalid window - {0}'.format(args['window']), 400)
        result = {}
        if 'ea' in args:
            ea = args['ea']
            success = idaapi.jumpto(ea)
            result['moved'] = success
        result['ea'] = self._hex(idaapi.get_screen_ea())
        return result

    def _get_segment_info(self, s):
        return {
            'name' : idaapi.get_true_segm_name(s),
            'ida_name' : idaapi.get_segm_name(s),
            'start' : self._hex(s.startEA),
            'end' : self._hex(s.endEA),
            'size' : self._hex(s.size())
        }

    @HTTPRequestHandler.route('segments')
    @check_ea
    def segments(self, args):
        if 'ea' in args:
            s = idaapi.getseg(args['ea'])
            if not s:
                raise IDARequestError('Invalid address', 400)
            return {'segment': self._get_segment_info(s)}
        else:
            m = {'segments': []}
            for i in range(idaapi.get_segm_qty()):
                s = idaapi.getnseg(i)
                m['segments'].append(self._get_segment_info(s))
            return m

    @HTTPRequestHandler.route('names')
    def names(self, args):
        m = {'names' : []}
        for n in idautils.Names():
            m['names'].append([self._hex(n[0]), n[1]])
        return m

    @HTTPRequestHandler.route('color')
    @check_color
    @check_ea
    @require_params('ea')
    def color(self, args):
        ea = args['ea']
        if 'color' in args:
            color = args['color']
            def f():
                idc.SetColor(ea, idc.CIC_ITEM, color)
            idaapi.execute_sync(f, idaapi.MFF_WRITE)
            idc.Refresh()
            return {}
        else:
            return {'color' : str(GetColor(ea, idc.CIC_ITEM))}

        
# Figure out when this is really needed
#def f():
#    idaapi.jumpto(ea) # DO STUFF
#idaapi.execute_sync(f, idaapi.MFF_FAST)

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
            self.host,self.port = self._get_netinfo()
        except:
            pass

        try:
            self.worker = Worker(self.host,self.port)
        except Exception as e:
            idaapi.msg("Error starting worker : " + str(e) + "\n")
            return
        self.worker.start()
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

