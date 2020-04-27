import os
import logging

import thug

from thug.ThugAPI.ThugOpts import ThugOpts
from thug.DOM.JSInspector import JSInspector

configuration_path = thug.__configuration_path__

log = logging.getLogger("Thug")
log.configuration_path = configuration_path
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None

log.ThugOpts = ThugOpts()

last_url = "https://www.google.com" 
log.last_url = last_url


class WindowDict(dict):
    def __setitem__(self, key, value):
        self[key] = value

    def __getitem__(self, key):
        return self[key]


class TestJSInspector(object):
    def test_dump_url(self):
        window = WindowDict()
        window.url = last_url

        inspector = JSInspector(window, object(), '')
        assert inspector.dump_url == last_url
