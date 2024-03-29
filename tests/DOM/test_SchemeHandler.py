import logging

import thug

from thug.DOM.SchemeHandler import SchemeHandler
from thug.Logging.ThugLogging import ThugLogging
from thug.ThugAPI.ThugOpts import ThugOpts

log = logging.getLogger("Thug")

configuration_path = thug.__configuration_path__
log.personalities_path = thug.__personalities_path__ if configuration_path else None
log.configuration_path = thug.__configuration_path__

log.ThugOpts = ThugOpts()
log.PyHooks = dict()

log.ThugLogging = ThugLogging()


class TestSchemeHandler(object):
    def test_hcp(self):
        handler = SchemeHandler()

        handler.handle_hcp(None, "test")
        handler.handle_hcp(None, "svr=foo")
        handler.handle_hcp(None, "svr=foo<defer>")
        handler.handle_hcp(None, "svr=foo<defer></script>")
