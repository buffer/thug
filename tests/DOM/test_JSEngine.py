import logging

import thug

from thug.DOM.JSEngine import JSEngine

log = logging.getLogger("Thug")
log.configuration_path = thug.__configuration_path__


class TestJSEngine(object):
    def test_jsobject(self):
        engine = JSEngine()
        assert engine.isJSObject(None) is False
