import os
import logging

import thug
from thug.Logging.ThugLogging import ThugLogging
from thug.ThugAPI.ThugOpts import ThugOpts


configuration_path = thug.__configuration_path__
log                    = logging.getLogger("Thug")
log.configuration_path = configuration_path
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None
log.ThugOpts           = ThugOpts()

thug_logging = ThugLogging(thug.__version__)


class TestThugLogging:
    def test_set_url(self):
        log.ThugOpts.maec11_logging = True
        thug_logging.set_url("https://www.example.com")
        assert thug_logging.url

    def test_add_code_snippet(self):
        pass

    def test_log_virustotal(self):
        pass

    def test_log_honeyagent(self):
        pass

    def test_log_androguard(self):
        pass

    def test_log_peepdf(self):
        pass

    def test_store_content(self):
        pass
