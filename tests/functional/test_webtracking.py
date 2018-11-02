import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestWebTracking(object):
    def do_perform_test(self, caplog, url, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_events('click,storage')
        thug.set_web_tracking()
        thug.disable_cert_logging()

        thug.log_init(url)
        thug.run_remote(url)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_google(self, caplog):
        expected = ['Domain starting with initial dot: .google.com']
        self.do_perform_test(caplog, "http://www.google.com", expected)
