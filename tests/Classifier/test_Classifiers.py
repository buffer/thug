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
        thug.add_textclassifier(os.path.join(self.signatures_path, "text_signature_5.yar"))
        thug.add_cookieclassifier(os.path.join(self.signatures_path, "cookie_signature_8.yar"))

        thug.add_htmlfilter(os.path.join(self.signatures_path, "html_filter_2.yar"))
        thug.add_jsfilter(os.path.join(self.signatures_path, "js_signature_2.yar"))
        thug.add_vbsfilter(os.path.join(self.signatures_path, "vbs_signature_6.yar"))
        thug.add_textfilter(os.path.join(self.signatures_path, "text_signature_5.yar"))
        thug.add_cookiefilter(os.path.join(self.signatures_path, "cookie_filter_9.yar"))

        with open(os.path.join(self.samples_path, sample), 'r') as fd:
            data = fd.read()

        log.HTMLClassifier.classify(os.path.basename(sample), data)
        log.TextClassifier.classify(os.path.basename(sample), data)
        log.TextClassifier.classify(os.path.basename(sample), data)
        log.CookieClassifier.classify(os.path.basename(sample), data)
        log.CookieClassifier.classify(os.path.basename(sample), data)

        log.HTMLClassifier.filter(os.path.basename(sample), data)
        log.JSClassifier.filter(os.path.basename(sample), data)
        log.VBSClassifier.filter(os.path.basename(sample), data)
        log.TextClassifier.filter(os.path.basename(sample), data)
        log.CookieClassifier.filter(os.path.basename(sample), data)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_html_classifier_1(self, caplog):
        sample   = os.path.join(self.samples_path, "test1.html")
        expected = ['[HTML Classifier] URL: test1.html (Rule: html_signature_1, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_html_filter_2(self, caplog):
        sample   = os.path.join(self.samples_path, "test2.html")
        expected = ['[HTMLFILTER Classifier] URL: test2.html (Rule: html_filter_2, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_js_filter_2(self, caplog):
        sample   = os.path.join(self.samples_path, "test2.html")
        expected = ['[JSFILTER Classifier] URL: test2.html (Rule: js_signature_2, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_text_classifier_5(self, caplog):
        sample   = os.path.join(self.samples_path, "test5.html")
        expected = ['[TEXT Classifier] URL: test5.html (Rule: text_signature_5, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_text_filter_5(self, caplog):
        sample   = os.path.join(self.samples_path, "test5.html")
        expected = ['[TEXTFILTER Classifier] URL: test5.html (Rule: text_signature_5, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_vbs_filter_6(self, caplog):
        sample   = os.path.join(self.samples_path, "test6.html")
        expected = ['[VBSFILTER Classifier] URL: test6.html (Rule: vbs_signature_6, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_cookie_classifier_8(self, caplog):
        sample   = os.path.join(self.samples_path, "cookie1.txt")
        expected = ['[COOKIE Classifier] URL: cookie1.txt (Rule: cookie_signature_8, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_cookie_filter_9(self, caplog):
        sample   = os.path.join(self.samples_path, "cookie2.txt")
        expected = ['[COOKIEFILTER Classifier] URL: cookie2.txt (Rule: cookie_filter_9, Classification: )']

        self.do_perform_test(caplog, sample, expected)
