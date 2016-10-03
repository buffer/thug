#!/usr/bin/env python
#
# HTTPSession.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

import sys
import datetime
import requests
import ssl

try:
    import urllib.parse as urlparse
    from urllib.parse import quote
except ImportError:
    import urlparse
    from urllib import quote

import logging
log = logging.getLogger("Thug")


class HTTPSession(object):
    def __init__(self, proxy = None):
        if proxy is None:
            proxy = log.ThugOpts.proxy

        self.__init_session(proxy)
        self.filecount = 0

    def __do_init_proxy(self, proxy):
        url = urlparse.urlparse(proxy)
        if not url.scheme:
            return False

        if not url.scheme.lower().startswith(('http', 'socks4', 'socks5')):
            return False

        self.session.proxies = {
            'http'  : proxy,
            'https' : proxy
        }

        return True

    def __init_proxy(self, proxy):
        if proxy is None:
            return

        if self.__do_init_proxy(proxy):
            return

        log.warning("[WARNING] Wrong proxy specified. Aborting the analysis!")
        sys.exit(0)

    def __init_session(self, proxy):
        self.session = requests.Session()
        self.__init_proxy(proxy)

    def _normalize_protocol_relative_url(self, window, url):
        if not url.startswith('//'):
            return url

        if window.url in ('about:blank', ):
            return 'http:%s' % (url, )

        base_url = urlparse.urlparse(window.url)
        if not base_url.scheme:
            return 'http:%s' % (url, )

        return "%s:%s" % (base_url.scheme, url)

    def _is_compatible(self, url, scheme):
        return url.startswith("%s:/" % (scheme, )) and not url.startswith("%s://" % (scheme, ))

    def _check_compatibility(self, url):
        for scheme in ("http", "https", ):
            if self._is_compatible(url, scheme):
                return "%s://%s" % (scheme, url.split("%s:/" % (scheme, ))[1], )

        return url

    def normalize_url(self, window, url):
        # Check the URL is not broken (i.e. http:/www.google.com) and
        # fix it if the broken URL option is enabled. 
        if log.ThugOpts.broken_url:
            url = self._check_compatibility(url)

        url = self._normalize_protocol_relative_url(window, url)
        url = quote(url, safe = "%/:=&?~#+!$,;'@()*[]")
        
        _url = urlparse.urlparse(url)

        # Check if a scheme handler is registered and calls the proper
        # handler in such case. This is how a real browser would handle
        # a specific scheme so if you want to add your own handler for 
        # analyzing specific schemes the proper way to go is to define 
        # a method named handle_<scheme> in the SchemeHandler and put 
        # the logic within such method.
        handler = getattr(log.SchemeHandler, 'handle_%s' % (_url.scheme, ), None)
        if handler:
            handler(window, url)
            return None

        if not _url.netloc:
            _url = urlparse.urljoin(window.url, url)
            log.warning("[Navigator URL Translation] %s --> %s", url, _url)
            return _url

        return url

    def build_http_headers(self, window, personality, headers):
        http_headers = { 
            'Cache-Control'   : 'no-cache',
            'Accept-Language' : 'en-US',
            'Accept'          : '*/*',
            'User-Agent'      :  personality
        }

        if window and window.url not in ('about:blank', ):
            http_headers['Referer'] = self.normalize_url(window, window.url)

        # REVIEW ME!
        #if window and window.doc.cookie:
        #    http_headers['Cookie'] = window.doc.cookie

        for name, value in headers.items():
            http_headers[name] = value

        return http_headers

    def fetch_ssl_certificate(self, url):
        _url = urlparse.urlparse(url)
        if _url.scheme not in ('https', ):
            return

        port = _url.port if  _url.port else 443
        certificate = ssl.get_server_certificate((_url.netloc, port), ssl_version = ssl.PROTOCOL_SSLv23)
        log.ThugLogging.log_certificate(url, certificate)

    def fetch(self, url, method = "GET", window = None, personality = None, headers = None, body = None):
        fetcher = getattr(self.session, method.lower(), None)
        if fetcher is None:
            log.ThugLogging.log_warning("Not supported method: %s" % (method, ))
            return None

        if headers is None:
            headers = dict()

        _headers = self.build_http_headers(window, personality, headers)
        response = fetcher(url, 
                           headers = _headers, 
                           timeout = 10,
                           verify  = False)
        
        self.filecount += 1
        log.WebTracking.inspect_response(response)
        return response

    def threshold_expired(self, url):
        if not log.ThugOpts.threshold:
            return False
        
        if self.filecount >= log.ThugOpts.threshold:
            log.ThugLogging.log_location(url, None, flags = {"error" : "Threshold Exceeded"})
            return True

        return False

    def timeout_expired(self, url):
        if log.ThugOpts.timeout is None:
            return False

        if datetime.datetime.now() > log.ThugOpts.timeout:
            log.ThugLogging.log_location(url, None, flags = {"error" : "Timeout"})
            return True

        return False

    def handle_status_code_error_404(self, response):
        log.ThugLogging.add_behavior_warn("[File Not Found] URL: %s" % (response.url, ))
        log.ThugLogging.log_location(response.url, None, flags = {"error" : "File Not Found"})

    def handle_status_code_error_400(self, response):
        log.ThugLogging.add_behavior_warn("[%s] URL: %s" % (response.reason, response.url, ))

    def handle_status_code_error_408(self, response):
        self.handle_status_code_error_400(response)

    def handle_status_code_error_500(self, response):
        self.handle_status_code_error_400(response)

    def handle_status_code_error(self, response):
        handler = getattr(self, "handle_status_error_code_%s" % (response.status_code, ), None)

        if handler is None:
            return False

        handler(response)
        return True

    @property
    def no_fetch(self):
        return log.ThugOpts.no_fetch

    def about_blank(self, url):
        return url.lower() in ('about:blank', )


import unittest

class HTTPSessionTest(unittest.TestCase):
    def setUp(self):
        self.check_ip_url = "http://ifconfig.me/ip"

    def testHTTPSession(self):
        s = HTTPSession()
        r = s.session.get("http://www.google.com")
        self.assertTrue(r.ok)

    def testHTTPSessionSOCKS(self):
        stor = HTTPSession()
        rtor = stor.session.get("https://www.dan.me.uk/torlist/")
        tor_exit_nodes = rtor.text.split("\n")

        s = HTTPSession(proxy = "socks5://127.0.0.1:9050")
        r = s.session.get(self.check_ip_url)
        ipaddress = r.text.replace("\n", "")
        
        self.assertIn(ipaddress, tor_exit_nodes)

    def testHTTPSessionNotSupportedMethod(self):
        s = HTTPSession()
        r = s.fetch("http://www.google.com", method = "NOTSUPPORTED")
        self.assertEqual(r, None)

    def testHTTPSessionGET(self):
        s = HTTPSession()
        r = s.fetch("http://www.google.com")
        self.assertTrue(r.ok)

if __name__ == '__main__':
    unittest.main()
