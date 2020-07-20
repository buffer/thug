import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestInspector(object):
    thug_path       = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    misc_path       = os.path.join(thug_path, "thug", "samples/misc")
    signatures_path = os.path.join(thug_path, "thug", "tests/signatures")

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
                    'thug/samples/misc/testInspector.html (Rule: OnlineID, Classification: )']

        self.do_perform_test(caplog, sample, expected)
