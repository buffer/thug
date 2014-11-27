#!/usr/bin/env python
#
# ThugOpts.py
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
import os
import datetime
import httplib2
import logging

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

from DOM.Personality import Personality

log = logging.getLogger("Thug")


class ThugOpts(dict):
    proxy_schemes = ('http', 'http2', 'socks4', 'socks5', )

    def __init__(self):
        self._proxy_info      = None
        self._proxy           = None
        self.local            = False
        self.extensive        = False
        self._threshold       = 0
        self._timeout         = None
        self._timeout_in_secs = None
        self.ast_debug        = False
        self.http_debug       = 0
        self._useragent       = 'winxpie60'
        self._referer         = 'about:blank'
        self._events          = list()
        self._delay           = 0
        self._file_logging    = False
        self._no_fetch        = False
        self._broken_url      = False
        self._vt_query        = False
        self._vt_submit       = False
        self._honeyagent      = True
        self._cache           = '/tmp/thug-cache-%s' % (os.getuid(), )
        self.Personality      = Personality()

    def set_proxy_info(self, proxy):
        self._proxy = proxy 

        p = urlparse.urlparse(proxy)

        if p.scheme.lower() not in self.proxy_schemes:
            log.warning('[ERROR] Invalid proxy scheme (valid schemes: http, http2, socks4, socks5)')
            sys.exit(0)

        proxy_scheme = p.scheme.upper()
        if proxy_scheme in ('HTTP2', ):
            proxy_scheme = 'HTTP_NO_TUNNEL'

        proxy_type = getattr(httplib2.socks, "PROXY_TYPE_%s" % proxy_scheme)
        self._proxy_info = httplib2.ProxyInfo(proxy_type = proxy_type,
                                              proxy_host = p.hostname,
                                              proxy_port = p.port if p.port else 8080,
                                              proxy_user = p.username,
                                              proxy_pass = p.password)

    def get_proxy_info(self):
        return self._proxy_info

    proxy_info = property(get_proxy_info, set_proxy_info)

    def get_useragent(self):
        return self._useragent

    def set_useragent(self, useragent):
        if not useragent in self.Personality:
            log.warning('[WARNING] Invalid User Agent provided (using default "%s")' % (self._useragent, ))
            return

        self._useragent = useragent

    useragent = property(get_useragent, set_useragent)

    def get_referer(self):
        return self._referer

    def set_referer(self, referer):
        self._referer = referer

    referer = property(get_referer, set_referer)

    def get_events(self):
        return self._events

    def set_events(self, events):
        for e in events.split(","):
            self._events.append(e.lower().strip())

    events = property(get_events, set_events)

    def get_delay(self):
        return self._delay

    def set_delay(self, timeout):
        try:
            _timeout = int(timeout)
        except:
            log.warning('[WARNING] Ignoring invalid delay value (should be an integer)')
            return

        self._delay = abs(_timeout)

    delay = property(get_delay, set_delay)

    def get_file_logging(self):
        return self._file_logging

    def set_file_logging(self, file_logging):
        self._file_logging = file_logging

    file_logging = property(get_file_logging, set_file_logging)

    def get_no_fetch(self):
        return self._no_fetch

    def set_no_fetch(self, fetch):
        self._no_fetch = fetch

    no_fetch = property(get_no_fetch, set_no_fetch)

    def get_cache(self):
        return self._cache

    def set_cache(self, cache):
        self._cache = cache

    cache = property(get_cache, set_cache)

    def get_threshold(self):
        return self._threshold

    def set_threshold(self, threshold):
        try:
            value = int(threshold)
        except:
            log.warning('[WARNING] Ignoring invalid threshold value (should be an integer)')
            return

        self._threshold = value

    threshold = property(get_threshold, set_threshold)

    def get_timeout(self):
        return self._timeout

    def set_timeout(self, timeout):
        self._timeout_in_secs = timeout

        try:
            seconds = int(timeout)
        except:
            log.warning('[WARNING] Ignoring invalid timeout value (should be an integer)')
            return

        now   = datetime.datetime.now()
        delta = datetime.timedelta(seconds = seconds)
        self._timeout = now + delta

    timeout = property(get_timeout, set_timeout)

    def get_broken_url(self):
        return self._broken_url

    def set_broken_url(self, mode):
        self._broken_url = mode

    broken_url = property(get_broken_url, set_broken_url)

    def get_vt_query(self):
        return self._vt_query

    def set_vt_query(self):
        self._vt_query = True

    vt_query = property(get_vt_query, set_vt_query)

    def get_vt_submit(self):
        return self._vt_submit

    def set_vt_submit(self):
        self._vt_submit = True

    vt_submit = property(get_vt_submit, set_vt_submit)

    def get_honeyagent(self):
        return self._honeyagent

    def set_honeyagent(self, enabled):
        self._honeyagent = enabled

    honeyagent = property(get_honeyagent, set_honeyagent)
