# requests-negotiate

An implementation of HTTP Negotiate authentication ([RFC 4559](http://tools.ietf.org/html/rfc4559)) for [requests](http://docs.python-requests.org/en/latest/).

Negotiate authentication is commonly used to provide Kerberos authentication through GSSAPI.

## Usage

Here's a trivial example:

    import requests
    import requests_negotiate

    auth = requests_negotiate.HTTPNegotiateAuth()
    response = requests.get('https://example.org/', auth=auth)

You'll need a valid Kerberos token — acquired using e.g. `kinit` — for this to work.

