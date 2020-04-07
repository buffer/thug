import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestImageProcessing(object):
    def do_perform_test(self, caplog, url, expected, type_ = "remote"):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_image_processing()
        thug.enable_cert_logging()
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
        expected = ['Antifork',
                    'HACKERS RESEARCH VIRTUAL LAB']

        self.do_perform_test(caplog, "https://www.antifork.org", expected)
