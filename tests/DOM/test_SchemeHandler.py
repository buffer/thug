import os
import logging

import thug

from thug.DOM.SchemeHandler import SchemeHandler
from thug.Logging.ThugLogging import ThugLogging
from thug.ThugAPI.ThugOpts import ThugOpts

log = logging.getLogger("Thug")

configuration_path = thug.__configuration_path__
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None
log.configuration_path = thug.__configuration_path__

log.ThugOpts = ThugOpts()
log.ThugLogging = ThugLogging(thug.__version__)


class TestSchemeHandler(object):
    def test_hcp(self):
        handler = SchemeHandler()

        handler.handle_hcp(None, "test")
        handler.handle_hcp(None, "svr=foo")
        handler.handle_hcp(None, "svr=foo<defer>")
        handler.handle_hcp(None, "svr=foo<defer></script>")
