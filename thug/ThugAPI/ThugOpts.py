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
import logging
import six.moves.urllib.parse as urlparse

from thug.DOM.Personality import Personality

log = logging.getLogger("Thug")


class ThugOpts(dict):
    proxy_schemes = ('http', 'socks4', 'socks5', )

    def __init__(self):
        super(ThugOpts, self).__init__()
        self._verbose           = False
        self._debug             = False
        self._proxy             = None
        self._raise_for_proxy   = True
        self.local              = False
        self.extensive          = False
        self._threshold         = 0
        self._connect_timeout   = 10
        self._timeout           = 600
        self.ast_debug          = False
        self.http_debug         = 0
        self._useragent         = 'winxpie60'
        self._referer           = 'about:blank'
        self._events            = list()
        self._delay             = 0
        self._attachment        = False
        self._file_logging      = False
        self._json_logging      = False
        self._es_logging        = False
        self._code_logging      = True
        self._cert_logging      = True
        self._features_logging  = False
        self._no_fetch          = False
        self._broken_url        = False
        self._vt_query          = False
        self._vt_submit         = False
        self._vt_runtime_apikey = None
        self._mongodb_address   = None
        self._web_tracking      = False
        self._honeyagent        = True
        self.activex_ready      = True
        self.Personality        = Personality()

    def set_verbose(self, verbose):
        self._verbose = verbose

    def get_verbose(self):
        return self._verbose

    verbose = property(get_verbose, set_verbose)

    def set_debug(self, debug):
        self._debug = debug

    def get_debug(self):
        return self._debug

    debug = property(get_debug, set_debug)

    def set_proxy(self, proxy):
        if not proxy:
            self._proxy = None
            return

        p = urlparse.urlparse(proxy)

        if p.scheme.lower() not in self.proxy_schemes:
            log.warning('[ERROR] Invalid proxy scheme (valid schemes: http, socks4, socks5)')
            sys.exit(0)

        self._proxy = proxy

    def get_proxy(self):
        return self._proxy

    proxy = property(get_proxy, set_proxy)

    def set_raise_for_proxy(self, raise_for_proxy):
        self._raise_for_proxy = raise_for_proxy

    def get_raise_for_proxy(self):
        return self._raise_for_proxy

    raise_for_proxy = property(get_raise_for_proxy, set_raise_for_proxy)

    def get_useragent(self):
        return self._useragent

    def set_useragent(self, useragent):
        if useragent not in self.Personality:
            log.warning('[WARNING] Invalid User Agent provided (using default "%s")', self._useragent)
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
        if not events:
            self._events = list()
            return

        for e in events.split(","):
            evt = e.lower().strip()

            if evt not in self._events:
                self._events.append(evt)

    events = property(get_events, set_events)

    def get_delay(self):
        return self._delay

    def set_delay(self, timeout):
        try:
            _timeout = int(timeout)
        except ValueError:
            log.warning('[WARNING] Ignoring invalid delay value (should be an integer)')
            return

        self._delay = abs(_timeout)

    delay = property(get_delay, set_delay)

    def get_attachment(self):
        return self._attachment

    def set_attachment(self, attachment):
        self._attachment = attachment

    attachment = property(get_attachment, set_attachment)

    def get_file_logging(self):
        return self._file_logging

    def set_file_logging(self, file_logging):
        self._file_logging = file_logging

    file_logging = property(get_file_logging, set_file_logging)

    def get_json_logging(self):
        return self._json_logging

    def set_json_logging(self, json_logging):
        self._json_logging = json_logging

    json_logging = property(get_json_logging, set_json_logging)

    def get_es_logging(self):
        return self._es_logging

    def set_es_logging(self, es_logging):
        self._es_logging = es_logging

    elasticsearch_logging = property(get_es_logging, set_es_logging)

    def get_code_logging(self):
        return self._code_logging

    def set_code_logging(self, code_logging):
        self._code_logging = code_logging

    code_logging = property(get_code_logging, set_code_logging)

    def get_cert_logging(self):
        return self._cert_logging

    def set_cert_logging(self, cert_logging):
        self._cert_logging = cert_logging

    cert_logging = property(get_cert_logging, set_cert_logging)

    def get_features_logging(self):
        return self._features_logging

    def set_features_logging(self, features_logging):
        self._features_logging = features_logging

    features_logging = property(get_features_logging, set_features_logging)

    def get_no_fetch(self):
        return self._no_fetch

    def set_no_fetch(self, fetch):
        self._no_fetch = fetch

    no_fetch = property(get_no_fetch, set_no_fetch)

    def get_threshold(self):
        return self._threshold

    def set_threshold(self, threshold):
        try:
            value = int(threshold)
        except ValueError:
            log.warning('[WARNING] Ignoring invalid threshold value (should be an integer)')
            return

        self._threshold = value

    threshold = property(get_threshold, set_threshold)

    def get_connect_timeout(self):
        return self._connect_timeout

    def set_connect_timeout(self, timeout):
        try:
            seconds = int(timeout)
        except ValueError:
            log.warning('[WARNING] Ignoring invalid connect timeout value (should be an integer)')
            return

        self._connect_timeout = seconds

    connect_timeout = property(get_connect_timeout, set_connect_timeout)

    def get_timeout(self):
        return self._timeout

    def set_timeout(self, timeout):
        try:
            seconds = int(timeout)
        except ValueError:
            log.warning('[WARNING] Ignoring invalid timeout value (should be an integer)')
            return

        self._timeout = seconds

    timeout = property(get_timeout, set_timeout)

    def get_broken_url(self):
        return self._broken_url

    def set_broken_url(self, mode):
        self._broken_url = mode

    broken_url = property(get_broken_url, set_broken_url)

    def get_vt_query(self):
        return self._vt_query

    def set_vt_query(self, value):
        self._vt_query = value

    vt_query = property(get_vt_query, set_vt_query)

    def get_vt_submit(self):
        return self._vt_submit

    def set_vt_submit(self, value):
        self._vt_submit = value

    vt_submit = property(get_vt_submit, set_vt_submit)

    def get_vt_runtime_apikey(self):
        return self._vt_runtime_apikey

    def set_vt_runtime_apikey(self, vt_apikey):
        self._vt_runtime_apikey = vt_apikey

    vt_runtime_apikey = property(get_vt_runtime_apikey, set_vt_runtime_apikey)

    def get_web_tracking(self):
        return self._web_tracking

    def set_web_tracking(self, enabled):
        self._web_tracking = enabled

    web_tracking = property(get_web_tracking, set_web_tracking)

    def get_honeyagent(self):
        return self._honeyagent

    def set_honeyagent(self, enabled):
        self._honeyagent = enabled

    honeyagent = property(get_honeyagent, set_honeyagent)

    def get_mongodb_address(self):
        return self._mongodb_address

    def set_mongodb_address(self, mongodb_address):
        self._mongodb_address = mongodb_address

    mongodb_address = property(get_mongodb_address, set_mongodb_address)
