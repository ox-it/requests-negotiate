import base64
import socket
import ssl

import logging

import gssapi
from requests.auth import AuthBase
import www_authenticate
from requests.packages.urllib3.connection import HTTPConnection
try:
    from requests.packages.urllib3.contrib.pyopenssl import WrappedSocket
except ImportError:
    # A dummy class, for which nothing will be an instance of it.
    WrappedSocket = type('WrappedSocket', (object,), {})

logger = logging.getLogger(__name__)


class HTTPNegotiateAuth(AuthBase):
    def __init__(self, service='HTTP', service_name=None,
                 negotiate_client_name=None):
        self.service = service
        self.service_name = service_name
        self.negotiate_client_name = negotiate_client_name

    def __call__(self, request):
        request.register_hook('response', self.handle_401)
        return request

    def get_hostname(self, response):
        assert isinstance(response.raw._connection, HTTPConnection)
        # Sometimes the connection is closed just before requests attempts to handle the 401, so let's open it again so
        # we can work out who we're talking to.
        if response.raw._connection.sock is None:
            response.raw._connection.connect()
        sock = response.raw._connection.sock
        # If pyopenssl is being used, we get a wrapped socket instead.
        if isinstance(sock, WrappedSocket):
            sock = sock.socket
        assert isinstance(sock, (ssl.SSLSocket, socket.socket))
        return socket.gethostbyaddr(sock.getpeername()[0])[0]

    @property
    def username(self):
        logging.debug("Obtaining username from GSSAPI")
        credential = gssapi.Credentials(usage='initiate')
        logging.debug("Username={0}".format(credential.name))
        return str(credential.name)

    def get_context(self, host):
        service_name = gssapi.Name(self.service_name or '{0}@{1}'.format(self.service, host),
                                   gssapi.NameType.hostbased_service)
        logging.debug("get_context(): service name={0}".format(service_name))
        if self.negotiate_client_name:
            creds = gssapi.Credentials(name=gssapi.Name(self.negotiate_client_name),
                                       usage='initiate')
        else:
            creds = None
        return gssapi.SecurityContext(name=service_name,
                                      creds=creds)

    def get_challenges(self, response):
        challenges = {}
        for k, v in response.headers.items():
             if k.lower() == 'www-authenticate':
                 challenges.update(www_authenticate.parse(v))
        return challenges

    def handle_401(self, response, **kwargs):
        logger.debug("Starting to handle 401 error")
        logger.debug(response.headers)
        challenges = self.get_challenges(response)
        logger.debug("auth_methods={0}".format(challenges))
        if 'negotiate' not in challenges:
            logger.debug("Giving up on negotiate auth")
            return response

        host = self.get_hostname(response)
        logger.debug("host={0}".format(host))
        ctx = self.get_context(host)

        logger.debug("ctx={0}".format(ctx))
        in_token = base64.b64decode(challenges['negotiate'].encode('ascii')) \
            if challenges['negotiate'] else None

        out_token = ctx.step(in_token)
        while response.status_code == 401 and not ctx.complete:
            response.content
            response.raw.release_conn()
            new_request = response.request.copy()
            new_request.headers['Authorization'] = \
                'Negotiate ' + base64.b64encode(out_token).decode('ascii')
            new_response = response.connection.send(new_request, **kwargs)
            new_response.history.append(response)
            new_response.request = new_request
            response = new_response
            challenges = self.get_challenges(response)
            if 'negotiate' in challenges:
                in_token = base64.b64decode(challenges['negotiate'].encode())
                out_token = ctx.step(in_token)
            else:
                break

        return response
