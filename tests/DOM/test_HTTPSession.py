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
