import base64
import re

import gssapi
from requests.auth import AuthBase
from requests.compat import urlparse

class HTTPNegotiateAuth(AuthBase):
    def __init__(self, service='HTTP', preempt=False):
        self.service = service
        self.contexts = {}
        self.preempt = preempt

    def __call__(self, request):
        host = urlparse(request.url).hostname
        if self.preempt or host in self.contexts:
            self.contexts[host] = ctx = self.get_context(host)
            token = ctx.step(None)
            request.headers['Authorization'] = 'Negotiate ' + base64.b64encode(token).decode('utf-8')
        request.register_hook('response', self.handle_401)
        return request

    def get_context(self, host):
        service_name = gssapi.Name('{0}@{1}'.format(self.service,
                                                    host),
                                   gssapi.C_NT_HOSTBASED_SERVICE)
        return gssapi.InitContext(service_name)


    authenticate_re = re.compile("""([a-z_\d]+)(=("([^\\"]*(\\.)?)*")|[a-z_\d]*)?(\s+,)?(\s+|$)""", re.I)
    def parse_authenticate_header(self, value):
        methods, method, name = {}, None, None
        while value:
           match = self.authenticate_re.match(value)
           if not match:
               return {}
           if not match.group(6) and match.group(7) is not None:
               name = match.group(1).title()
               methods[name] = method = {}
           else:
               if match.group(2): # foo=bar
                   value = match.group(4)
                   if value.startswith('"'):
                       value = value[1:-1]
                   method[match.group(1)] = value.replace(r'\"', '"')
               else: # it's not really a paramter
                   methods[name] = match.group(1)
           value = value[match.end():]
        return methods

    def handle_401(self, response, **kwargs):
        auth_methods = self.parse_authenticate_header(response.headers.get('WWW-Authenticate', ''))
        if 'Negotiate' not in auth_methods:
            return response

        host = urlparse(response.url).hostname
        if host in self.contexts:
            ctx = self.contexts[host]
        else:
            ctx = self.contexts[host] = self.get_context(host)

        while not ctx.established:
            response.content
            response.raw.release_conn()
            prep = response.request.copy()
            in_token = auth_methods['Negotiate'] or None
            if in_token:
                in_token = base64.b64decode(in_token).decode('utf-8')
            out_token = ctx.step(in_token)
            prep.headers['Authorization'] = 'Negotiate ' + base64.b64encode(out_token).decode('utf-8')
            _r = response.connection.send(prep, **kwargs)
            _r.history.append(response)
            _r.request = prep

        return _r

