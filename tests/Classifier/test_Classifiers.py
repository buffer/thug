import os
import shutil
import logging

from thug.ThugAPI.ThugAPI import ThugAPI
from thug.Logging.ThugLogging import ThugLogging

log = logging.getLogger("Thug")


class TestClassifiers:
    cwd_path        = os.path.dirname(os.path.realpath(__file__))
    samples_path    = os.path.join(cwd_path, os.pardir, os.pardir, "samples/classifiers")
    signatures_path = os.path.join(cwd_path, os.pardir, os.pardir, "tests/signatures")

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()
        thug.log_init(sample)

        thug.add_htmlclassifier(os.path.join(self.signatures_path, "html_signature_1.yar"))
        thug.add_htmlfilter(os.path.join(self.signatures_path, "html_filter_2.yar"))
        thug.add_jsfilter(os.path.join(self.signatures_path, "js_signature_2.yar"))

        with open(os.path.join(self.samples_path, sample), 'r') as fd:
            html = fd.read()

        log.HTMLClassifier.classify(os.path.basename(sample), html)
        log.HTMLClassifier.filter(os.path.basename(sample), html)
        log.JSClassifier.filter(os.path.basename(sample), html)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_html_classifier1(self, caplog):
        sample   = os.path.join(self.samples_path, "test1.html")
        expected = ['[HTML Classifier] URL: test1.html (Rule: html_signature_1, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_html_filter2(self, caplog):
        sample   = os.path.join(self.samples_path, "test2.html")
        expected = ['[HTMLFILTER Classifier] URL: test2.html (Rule: html_filter_2, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_js_filter2(self, caplog):
        sample   = os.path.join(self.samples_path, "test2.html")
        expected = ['[JSFILTER Classifier] URL: test2.html (Rule: js_signature_2, Classification: )']

        self.do_perform_test(caplog, sample, expected)
