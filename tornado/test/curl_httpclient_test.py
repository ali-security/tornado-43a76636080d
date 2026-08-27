# coding: utf-8
from __future__ import absolute_import, division, print_function

from hashlib import md5
import os
import ssl

from tornado.escape import native_str, utf8
from tornado.httpclient import HTTPRequest, HTTPClientError
from tornado.locks import Event
from tornado.netutil import ssl_options_to_context
from tornado.stack_context import ExceptionStackContext
from tornado.testing import AsyncHTTPSTestCase, AsyncHTTPTestCase, gen_test
from tornado.test import httpclient_test
from tornado.test.util import unittest, ignore_deprecation
from tornado.web import Application, RequestHandler


try:
    import pycurl  # type: ignore
except ImportError:
    pycurl = None

if pycurl is not None:
    from tornado.curl_httpclient import CurlAsyncHTTPClient


@unittest.skipIf(pycurl is None, "pycurl module not present")
class CurlHTTPClientCommonTestCase(httpclient_test.HTTPClientCommonTestCase):
    def get_http_client(self):
        client = CurlAsyncHTTPClient(defaults=dict(allow_ipv6=False))
        # make sure AsyncHTTPClient magic doesn't give us the wrong class
        self.assertTrue(isinstance(client, CurlAsyncHTTPClient))
        return client


class DigestAuthHandler(RequestHandler):
    def initialize(self, username, password):
        self.username = username
        self.password = password

    def get(self):
        realm = 'test'
        opaque = 'asdf'
        # Real implementations would use a random nonce.
        nonce = "1234"

        auth_header = self.request.headers.get('Authorization', None)
        if auth_header is not None:
            auth_mode, params = auth_header.split(' ', 1)
            assert auth_mode == 'Digest'
            param_dict = {}
            for pair in params.split(','):
                k, v = pair.strip().split('=', 1)
                if v[0] == '"' and v[-1] == '"':
                    v = v[1:-1]
                param_dict[k] = v
            assert param_dict['realm'] == realm
            assert param_dict['opaque'] == opaque
            assert param_dict['nonce'] == nonce
            assert param_dict['username'] == self.username
            assert param_dict['uri'] == self.request.path
            h1 = md5(utf8('%s:%s:%s' % (self.username, realm, self.password))).hexdigest()
            h2 = md5(utf8('%s:%s' % (self.request.method,
                                     self.request.path))).hexdigest()
            digest = md5(utf8('%s:%s:%s' % (h1, nonce, h2))).hexdigest()
            if digest == param_dict['response']:
                self.write('ok')
            else:
                self.write('fail')
        else:
            self.set_status(401)
            self.set_header('WWW-Authenticate',
                            'Digest realm="%s", nonce="%s", opaque="%s"' %
                            (realm, nonce, opaque))


class CustomReasonHandler(RequestHandler):
    def get(self):
        self.set_status(200, "Custom reason")


class CustomFailReasonHandler(RequestHandler):
    def get(self):
        self.set_status(400, "Custom reason")


@unittest.skipIf(pycurl is None, "pycurl module not present")
class CurlHTTPClientTestCase(AsyncHTTPTestCase):
    def setUp(self):
        super(CurlHTTPClientTestCase, self).setUp()
        self.http_client = self.create_client()

    def get_app(self):
        return Application([
            ('/digest', DigestAuthHandler, {'username': 'foo', 'password': 'bar'}),
            ('/digest_non_ascii', DigestAuthHandler, {'username': 'foo', 'password': 'barユ£'}),
            ('/custom_reason', CustomReasonHandler),
            ('/custom_fail_reason', CustomFailReasonHandler),
        ])

    def create_client(self, **kwargs):
        return CurlAsyncHTTPClient(force_instance=True,
                                   defaults=dict(allow_ipv6=False),
                                   **kwargs)

    @gen_test
    def test_prepare_curl_callback_stack_context(self):
        exc_info = []
        error_event = Event()

        def error_handler(typ, value, tb):
            exc_info.append((typ, value, tb))
            error_event.set()
            return True

        with ignore_deprecation():
            with ExceptionStackContext(error_handler):
                request = HTTPRequest(self.get_url('/custom_reason'),
                                      prepare_curl_callback=lambda curl: 1 / 0)
        yield [error_event.wait(), self.http_client.fetch(request)]
        self.assertEqual(1, len(exc_info))
        self.assertIs(exc_info[0][0], ZeroDivisionError)

    def test_digest_auth(self):
        response = self.fetch('/digest', auth_mode='digest',
                              auth_username='foo', auth_password='bar')
        self.assertEqual(response.body, b'ok')

    def test_custom_reason(self):
        response = self.fetch('/custom_reason')
        self.assertEqual(response.reason, "Custom reason")

    def test_fail_custom_reason(self):
        response = self.fetch('/custom_fail_reason')
        self.assertEqual(str(response.error), "HTTP 400: Custom reason")

    def test_failed_setup(self):
        self.http_client = self.create_client(max_clients=1)
        for i in range(5):
            with ignore_deprecation():
                response = self.fetch(u'/ユニコード')
            self.assertIsNot(response.error, None)

            with self.assertRaises((UnicodeEncodeError, HTTPClientError)):
                # This raises UnicodeDecodeError on py3 and
                # HTTPClientError(404) on py2. The main motivation of
                # this test is to ensure that the UnicodeEncodeError
                # during the setup phase doesn't lead the request to
                # be dropped on the floor.
                response = self.fetch(u'/ユニコード', raise_error=True)

    def test_digest_auth_non_ascii(self):
        response = self.fetch('/digest_non_ascii', auth_mode='digest',
                              auth_username='foo', auth_password='barユ£')
        self.assertEqual(response.body, b'ok')


def no_connection_reuse(curl):
    """Force a complete connection setup for a request.

    The libcurl versions available on this test matrix do not take the
    per-request credentials into account when they look for a cached
    connection or a cached TLS session, so a reused connection could show the
    server whatever the *previous* request sent, independently of what this
    handle is configured with now. Disabling that caching keeps the assertions
    of the tests below about the options of the request that made them.
    """
    curl.setopt(pycurl.FRESH_CONNECT, 1)
    curl.setopt(pycurl.FORBID_REUSE, 1)
    curl.setopt(pycurl.SSL_SESSIONID_CACHE, 0)


class ProxyAuthEchoHandler(RequestHandler):
    def get(self):
        if self.request.headers.get('Proxy-Authorization', None) is not None:
            self.write('proxy auth: %s' % self.request.headers['Proxy-Authorization'])
        else:
            self.write('no proxy auth')


@unittest.skipIf(pycurl is None, "pycurl module not present")
class CurlHTTPClientReuseProxyAuthTestCase(AsyncHTTPTestCase):
    def get_app(self):
        # Note that we don't properly support proxy-style requests, but it works well enough
        # for this test if we start the url matcher with a wildcard.
        return Application([('.*/proxy_auth', ProxyAuthEchoHandler)])

    def get_http_client(self):
        # max_clients=1 forces us to reuse curl "easy handles". This is a regression test for
        # a bug in which proxy credentials were not cleared between requests.
        return CurlAsyncHTTPClient(force_instance=True,
                                   defaults=dict(allow_ipv6=False),
                                   max_clients=1)

    def test_reuse_proxy_credentials(self):
        # Proxy credentials used on one request should not be automatically reused
        # by another request.
        response = self.fetch('/proxy_auth',
                              proxy_host='127.0.0.1',
                              proxy_port=self.get_http_port(),
                              proxy_username='foo',
                              proxy_password='bar',
                              prepare_curl_callback=no_connection_reuse)
        self.assertEqual(response.body, b'proxy auth: Basic Zm9vOmJhcg==')
        response = self.fetch('/proxy_auth',
                              proxy_host='127.0.0.1',
                              proxy_port=self.get_http_port(),
                              prepare_curl_callback=no_connection_reuse)
        self.assertEqual(response.body, b'no proxy auth')


class ClientCertEchoHandler(RequestHandler):
    def get(self):
        cert = self.request.get_ssl_certificate()
        if cert is not None:
            # The python 2 ssl module returns unicode strings here while python 3
            # returns str, which changes the repr of the tuple. Normalize to the
            # native string type so the assertion is the same on all versions.
            subject = tuple(tuple((native_str(k), native_str(v)) for k, v in rdn)
                            for rdn in cert['subject'])
            self.write('client cert: %s' % (subject,))
        else:
            self.write('no client cert')


@unittest.skipIf(pycurl is None, "pycurl module not present")
class CurlHTTPClientReuseCertsTestCase(AsyncHTTPSTestCase):
    def get_app(self):
        return Application([('.*/client_cert', ClientCertEchoHandler)])

    def get_http_client(self):
        return CurlAsyncHTTPClient(force_instance=True,
                                   defaults=dict(allow_ipv6=False,
                                                 validate_cert=False),
                                   max_clients=1)

    def get_httpserver_options(self):
        ssl_ctx = ssl_options_to_context(self.get_ssl_options())
        ssl_ctx.verify_mode = ssl.CERT_OPTIONAL
        return dict(ssl_options=ssl_ctx)

    def get_ssl_options(self):
        opts = super(CurlHTTPClientReuseCertsTestCase, self).get_ssl_options()
        opts['ca_certs'] = os.path.join(os.path.dirname(__file__), 'curl_test.crt')
        return opts

    def test_reuse_certs(self):
        # Client certs used on one request should not be automatically reused
        # by another request.
        response = self.fetch(
            self.get_url('/client_cert'),
            client_cert=os.path.join(os.path.dirname(__file__), 'curl_test.crt'),
            client_key=os.path.join(os.path.dirname(__file__), 'curl_test.key'),
            prepare_curl_callback=no_connection_reuse)
        self.assertEqual(
            response.body, b"client cert: ((('commonName', 'foo.example.com'),),)")
        response = self.fetch(self.get_url('/client_cert'),
                              prepare_curl_callback=no_connection_reuse)
        self.assertEqual(response.body, b'no client cert')
