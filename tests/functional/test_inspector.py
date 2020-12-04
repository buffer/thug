import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestInspector(object):
    cwd_path        = os.path.dirname(os.path.realpath(__file__))
    misc_path       = os.path.join(cwd_path, os.pardir, "samples/misc")
    signatures_path = os.path.join(cwd_path, os.pardir, "signatures")

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()

        thug.set_useragent('winxpie70')
        thug.set_ssl_verify()
        thug.log_init(sample)

        thug.add_htmlclassifier(os.path.join(self.signatures_path, "inspector.yar"))

        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_inspector_1(self, caplog):
        sample   = os.path.join(self.misc_path, "testInspector.html")
        expected = ['[HTMLInspector] Detected potential code obfuscation',
                    '[HTML Classifier]',
                    'samples/misc/testInspector.html (Rule: OnlineID, Classification: )']

        self.do_perform_test(caplog, sample, expected)
