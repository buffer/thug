import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestClassifiers(object):
    thug_path        = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    classifiers_path = os.path.join(thug_path, "thug", "samples/classifiers")
    signatures_path  = os.path.join(thug_path, "thug", "tests/signatures")

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()

        thug.set_useragent('winxpie70')
        thug.disable_cert_logging()

        thug.log_init(sample)

        thug.add_htmlclassifier(os.path.join(self.signatures_path, "html_signature1.yar"))
        thug.add_jsclassifier(os.path.join(self.signatures_path, "js_signature1.yar"))
        
        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_test1(self, caplog):
        sample   = os.path.join(self.classifiers_path, "test1.html")
        expected = ['[HTML Classifier]',
                    'thug/samples/classifiers/test1.html (Rule: test1, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_test2(self, caplog):
        sample   = os.path.join(self.classifiers_path, "test2.html")
        expected = ['[JS Classifier]',
                    'thug/samples/classifiers/test2.html (Rule: test2, Classification: )']

        self.do_perform_test(caplog, sample, expected)
