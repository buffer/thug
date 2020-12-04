import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestScreenshot(object):
    def do_perform_test(self, caplog, url, expected, type_ = "remote"):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.disable_screenshot()
        thug.enable_screenshot()
        thug.set_file_logging()
        thug.set_json_logging()
        thug.set_ssl_verify()
        thug.log_init(url)

        m = getattr(thug, "run_{}".format(type_))
        m(url)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_antifork(self, caplog):
        expected = []
        self.do_perform_test(caplog, "https://buffer.antifork.org", expected)

    def test_youtube(self, caplog):
        expected = []
        self.do_perform_test(caplog, "https://www.youtube.com", expected)
