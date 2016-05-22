import base64
import re
import logging

import gssapi
from requests.auth import AuthBase
from requests.compat import urlparse
import www_authenticate


logger = logging.getLogger(__name__)


class HTTPNegotiateAuth(AuthBase):
    def __init__(self, service='HTTP', service_name=None,
                 negotiate_client_name=None, preempt=False):
        self.service = service
        self.service_name = service_name
        self.contexts = {}
        self.preempt = preempt
        self.negotiate_client_name = negotiate_client_name

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

        host = urlparse(response.url).hostname
        logger.debug("host={0}".format(host))
        if host in self.contexts:
            ctx = self.contexts[host]
        else:
            ctx = self.contexts[host] = self.get_context(host)

        logger.debug("ctx={0}".format(ctx))
        in_token = base64.b64decode(challenges['negotiate']) \
            if challenges['negotiate'] else None

        out_token = base64.b64encode(ctx.step(in_token))
        while response.status_code == 401 and not ctx.complete:
            response.content
            response.raw.release_conn()
            new_request = response.request.copy()
            new_request.headers['Authorization'] = 'Negotiate ' + out_token
            new_response = response.connection.send(new_request, **kwargs)
            new_response.history.append(response)
            new_response.request = new_request
            response = new_response
            challenges = self.get_challenges(response)
            in_token = base64.b64decode(challenges['negotiate'])
            out_token = ctx.step(in_token)
            if out_token:
                out_token = base64.b64encode(out_token)

        return response
