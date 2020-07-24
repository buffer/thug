import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestBrokenURL(object):
    def do_perform_test(self, caplog, url, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_broken_url()
        thug.set_ssl_verify()
        thug.log_init(url)

        thug.run_remote(url)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_broken_1(self, caplog):
        url      = 'https:/buffer.antifork.org'
        expected = ['[window open redirection] about:blank -> https://buffer.antifork.org', ]

        self.do_perform_test(caplog, url, expected)

    def test_broken_2(self, caplog):
        url      = 'https://buffer.antifork.org'
        expected = ['[window open redirection] about:blank -> https://buffer.antifork.org', ]

        self.do_perform_test(caplog, url, expected)
