import base64
import re
import logging

import gssapi
from requests.auth import AuthBase
from requests.compat import urlparse


logger = logging.getLogger(__name__)


class HTTPNegotiateAuth(AuthBase):
    def __init__(self, service='HTTP', preempt=False):
        self.service = service
        self.contexts = {}
        self.preempt = preempt

    def __call__(self, request):
        host = urlparse(request.url).hostname
        if self.preempt or host in self.contexts:
            logger.debug("__call__(): pre-emptively sending authorization"
                         "header")
            self.contexts[host] = ctx = self.get_context(host)
            token = ctx.step(None)
            token_b64 = base64.b64encode(token).decode('utf-8')
            request.headers['Authorization'] = 'Negotiate ' + token_b64
        request.register_hook('response', self.handle_401)
        return request

    @property
    def username(self):
        logging.debug("Obtaining username from GSSAPI")
        credential = gssapi.Credential(usage=gssapi.C_INITIATE)
        logging.debug("Username={0}".format(credential.name))
        return str(credential.name)

    def get_context(self, host):
        service_name = gssapi.Name('{0}@{1}'.format(self.service,
                                                    host),
                                   gssapi.C_NT_HOSTBASED_SERVICE)
        logging.debug("get_context(): service name={0}".format(service_name))
        return gssapi.InitContext(service_name)

    tchar = r'[^"\\\(\),/:;<=>?@\[\]\{\}\s]'
    regex = ('''(?P<token>{tchar}+)'''
             '''(\s*=\s*(?P<param>(".*([^\\\\]|)")|{tchar}*))?'''
             '''\s*,?\s*'''
            ).format(tchar=tchar)
    logger.debug("authenticate header regex: " + regex)
    authenticate_re = re.compile(regex, re.I)

    def parse_authenticate_header(self, value):
        logger.debug("parse_authenticate_header: values={0}".format(value))
        methods, method, name = {}, None, None
        for match in self.authenticate_re.finditer(value):
            logger.debug("Match={0}".format(match.group(0)))
            if not match:
                logger.debug("Error matching header")
                return {}
            if match.group("param") is None:
                logger.debug("token: " + match.group("token"))
                name = match.group("token").title()
                methods[name] = method = {}
            else:
                value = match.group("param")
                logger.debug(
                    "param: {0} = {1}".format(match.group("token"), value)
                )
                if value != "":
                    if value.startswith('"'):
                        value = value[1:-1]
                    method[match.group("token")] = value.replace(r'\"', '"')
                else:  # it's not really a paramter
                    methods[name] = match.group("token")
            value = value[match.end():]
        return methods

    def handle_401(self, response, **kwargs):
        logger.debug("Starting to handle 401 error")
        logger.debug(response.headers)
        auth_methods = self.parse_authenticate_header(
            response.headers.get('WWW-Authenticate', '')
        )
        logger.debug("auth_methods={0}".format(auth_methods))
        if 'Negotiate' not in auth_methods:
            logger.debug("Giving up on negotiate auth")
            return response

        host = urlparse(response.url).hostname
        logger.debug("host={0}".format(host))
        if host in self.contexts:
            ctx = self.contexts[host]
        else:
            ctx = self.contexts[host] = self.get_context(host)

        logger.debug("ctx={0}".format(ctx))
        while not ctx.established:
            response.content
            response.raw.release_conn()
            prep = response.request.copy()
            in_token = auth_methods['Negotiate'] or None
            if in_token:
                logger.debug("Server token: {0}".format(in_token))
                in_token = base64.b64decode(in_token).decode('utf-8')
            out_token = ctx.step(in_token)
            out_token_b64 = base64.b64encode(out_token).decode('utf-8')
            prep.headers['Authorization'] = 'Negotiate ' + out_token_b64
            logger.debug("Sending response token: {0}".format(out_token_b64))
            _r = response.connection.send(prep, **kwargs)
            _r.history.append(response)
            _r.request = prep

        return _r
