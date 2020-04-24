import os
import logging
import pytest

import thug

from thug.ThugAPI.ThugOpts import ThugOpts
from thug.DOM.HTTPSession import HTTPSession

configuration_path = thug.__configuration_path__

log = logging.getLogger("Thug")
log.configuration_path = configuration_path
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None

log.ThugOpts = ThugOpts()


class WindowDict(dict):
    def __setitem__(self, key, value):
        self[key] = value

    def __getitem__(self, key):
        return self[key]


class TestHTTPSession(object):
    def test_invalid_proxy_1(self):
        with pytest.raises(SystemExit):
            s = HTTPSession('invalid')

    def test_invalid_proxy_2(self):
        with pytest.raises(SystemExit):
            s = HTTPSession('foo://bar')

    def test_invalid_proxy_3(self):
        with pytest.raises(ValueError):
            s = HTTPSession('socks5://127.0.0.1:10000')

    def test_valid_proxy(self):
        s = HTTPSession(proxy = 'http://antifork.org:443')

    def test_normalize_1(self):
        window = WindowDict()
        window.url = 'about:blank'

        s = HTTPSession()
        url = s._normalize_protocol_relative_url(window, '//www.google.com')
        assert url == 'http://www.google.com'

    def test_normalize_2(self):
        window = WindowDict()
        window.url = 'www.google.com'

        s = HTTPSession()
        url = s._normalize_protocol_relative_url(window, '//www.google.com')
        assert url == 'http://www.google.com'
