# requests-negotiate

An implementation of HTTP Negotiate authentication ([RFC 4559](http://tools.ietf.org/html/rfc4559)) for [requests](http://docs.python-requests.org/en/latest/).

Negotiate authentication is commonly used to provide Kerberos authentication through GSSAPI.

## Usage

Here's a trivial example:

    import requests
    import requests_negotiate

    auth = requests_negotiate.HTTPNegotiateAuth()
    response = requests.get('https://example.org/', auth=auth)

You'll need a valid Kerberos ticket — acquired using e.g. `kinit` — for this to work.

### Options

You can instantiate an ``HTTPNegotiateAuth`` with the following optional parameters:

* ``service`` — A Kerberos principal is generally composed of a service name (e.g. 'HTTP') and a hostname, separated by a slash ('/'). This lets you override the default service of ``'HTTP'``.
* ``service_name`` — Overrides the full service name (e.g. ``'HTTP/example.org'``)
* ``negotiate_client_name`` — Explicitly specify which client principal to authenticate as. Particularly useful when you're using a credential cache collection.
* ``preempt`` — Attempt Negotiate authentication before it is offered.

