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

import logging
import sys
import socket
import ssl
import six.moves.urllib.parse as urlparse
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

log = logging.getLogger("Thug")


class HTTPSession(object):
    def __init__(self, proxy = None):
        if proxy is None:
            proxy = log.ThugOpts.proxy

        self.__init_session(proxy)
        self.filecount = 0

    def __check_proxy_alive(self, hostname, port):
        s = socket.create_connection((hostname, port), 5.0)
        s.close()

    def __do_init_proxy(self, proxy):
        url = urlparse.urlparse(proxy)
        if not url.scheme:
            return False

        if not url.scheme.lower().startswith(('http', 'socks4', 'socks5')):
            return False

        try:
            self.__check_proxy_alive(url.hostname, url.port)
        except Exception:
            log.critical("[CRITICAL] Proxy not available. Aborting the analysis!")

            if log.ThugOpts.raise_for_proxy:
                raise ValueError("[CRITICAL] Proxy not available")

            sys.exit(0) # pragma: no cover

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

        log.critical("[CRITICAL] Wrong proxy specified. Aborting the analysis!")
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
        # Do not normalize Data URI scheme
        if url.lower().startswith('url=') or url.lower().startswith('data:'):
            return url

        if url.startswith('#'):
            log.warning("[INFO] Ignoring anchor: %s", url)
            return None

        # Check the URL is not broken (i.e. http:/www.google.com) and
        # fix it if the broken URL option is enabled.
        if log.ThugOpts.broken_url:
            url = self._check_compatibility(url)

        url = self._normalize_protocol_relative_url(window, url)

        try:
            url = urlparse.quote(url, safe = "%/:=&?~#+!$,;'@()*[]{}")
        except KeyError: # pragma: no cover
            pass

        _url = urlparse.urlparse(url)

        base_url = None
        last_url = getattr(log, 'last_url', None)

        for _base_url in (last_url, window.url, ):
            if not _base_url:
                continue

            base_url = _base_url
            p_base_url = urlparse.urlparse(base_url)
            if p_base_url.scheme:
                break

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

        if not _url.netloc and base_url:
            _url = urlparse.urljoin(base_url, url)
            log.warning("[Navigator URL Translation] %s --> %s", url, _url)
            return _url

        return url

    def check_equal_urls(self, url, last_url):
        return urlparse.unquote(url) in (urlparse.unquote(last_url), )

    def build_http_headers(self, window, personality, headers):
        http_headers = {
            'Cache-Control'   : 'no-cache',
            'Accept-Language' : 'en-US',
            'Accept'          : '*/*',
            'User-Agent'      :  personality
        }

        if window and window.url not in ('about:blank', ):
            referer = window.url if window.url.startswith('http') else 'http://{}'.format(window.url)
            http_headers['Referer'] = referer

        # REVIEW ME!
        # if window and window.doc.cookie:
        #    http_headers['Cookie'] = window.doc.cookie

        for name, value in headers.items():
            http_headers[name] = value

        return http_headers

    def fetch_ssl_certificate(self, url):
        if not log.ThugOpts.cert_logging:
            return

        _url = urlparse.urlparse(url)
        if _url.scheme not in ('https', ):
            return

        port = _url.port if _url.port else 443

        try:
            certificate = ssl.get_server_certificate((_url.netloc, port), ssl_version = ssl.PROTOCOL_SSLv23)
            log.ThugLogging.log_certificate(url, certificate)
        except Exception as e: # pragma: no cover
            log.warning("[SSL ERROR] %s", str(e))

    def fetch(self, url, method = "GET", window = None, personality = None, headers = None, body = None):
        if log.URLClassifier.filter(url):
            return None

        if url.startswith("data:"):
            log.DFT._handle_data_uri(url)
            return None

        fetcher = getattr(self.session, method.lower(), None)
        if fetcher is None: # pragma: no cover
            log.warning("Not supported method: %s", method)
            return None

        if headers is None: # pragma: no cover
            headers = dict()

        _headers = self.build_http_headers(window, personality, headers)
        response = None

        try:
            response = fetcher(url,
                               headers = _headers,
                               timeout = log.ThugOpts.connect_timeout,
                               data    = body,
                               verify  = log.ThugOpts.ssl_verify)
        except requests.ConnectionError as e:
            log.warning("[HTTPSession] %s", str(e))

        if not response.ok:
            return None

        log.ThugLogging.retrieved_urls.add(url)

        self.filecount += 1

        if log.ThugOpts.web_tracking:
            log.WebTracking.inspect_response(response)

        return response

    def threshold_expired(self, url):
        if not log.ThugOpts.threshold:
            return False

        if self.filecount >= log.ThugOpts.threshold:
            log.ThugLogging.log_location(url, None, flags = {"error" : "Threshold Exceeded"})
            return True

        return False

    @property
    def no_fetch(self):
        return log.ThugOpts.no_fetch

    def about_blank(self, url):
        return url.lower() in ('about:blank', )

    def get_cookies(self):
        return self.session.cookies

    def set_cookies(self, name, value):
        self.session.cookies.set(name, value)

    cookies = property(get_cookies, set_cookies)
