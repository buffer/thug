import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestVirusTotal(object):
    def do_perform_test(self, caplog, url, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_vt_query()
        thug.set_vt_submit()
        thug.disable_cert_logging()
        thug.set_features_logging()
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

    def test_pdf(self, caplog):
        expected = ['[VirusTotal] Sample b3e2a017367a5acd4ad32e2b9b3e6a3a analysis ratio: 0/53', ]
        self.do_perform_test(caplog, "https://buffer.antifork.org/linux/kernel-api.pdf", expected)
