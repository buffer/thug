import os
import shutil
import hashlib
import logging

from thug.ThugAPI.ThugAPI import ThugAPI
from thug.Logging.ThugLogging import ThugLogging

log = logging.getLogger("Thug")


class TestClassifiers:
    cwd_path        = os.path.dirname(os.path.realpath(__file__))
    samples_path    = os.path.join(cwd_path, os.pardir, "samples/classifiers")
    test_files_path = os.path.join(cwd_path, os.pardir, "test_files")
    signatures_path = os.path.join(cwd_path, os.pardir, "signatures")

    def sample_passthrough(self, sample, md5):
        pass

    def image_passthrough(self, url, text):
        pass

    def cookie_passthrough(self, url, cookie):
        pass

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()
        thug.log_init(sample)

        thug.add_htmlclassifier(os.path.join(self.signatures_path, "html_signature_1.yar"))
        thug.add_textclassifier(os.path.join(self.signatures_path, "text_signature_5.yar"))
        thug.add_cookieclassifier(os.path.join(self.signatures_path, "cookie_signature_8.yar"))
        thug.add_sampleclassifier(os.path.join(self.signatures_path, "sample_signature_10.yar"))
        thug.add_imageclassifier(os.path.join(self.signatures_path, "image_signature_14.yar"))

        thug.add_htmlfilter(os.path.join(self.signatures_path, "html_filter_2.yar"))
        thug.add_jsfilter(os.path.join(self.signatures_path, "js_signature_2.yar"))
        thug.add_vbsfilter(os.path.join(self.signatures_path, "vbs_signature_6.yar"))
        thug.add_textfilter(os.path.join(self.signatures_path, "text_signature_5.yar"))
        thug.add_cookiefilter(os.path.join(self.signatures_path, "cookie_filter_9.yar"))
        thug.add_samplefilter(os.path.join(self.signatures_path, "sample_filter_11.yar"))
        thug.add_imagefilter(os.path.join(self.signatures_path, "image_filter_16.yar"))

        thug.add_htmlclassifier(os.path.join(self.signatures_path, "not_existing.yar"))
        thug.add_htmlfilter(os.path.join(self.signatures_path, "not_existing.yar"))
        thug.add_customclassifier('wrong_type', 'wrong_method')
        thug.add_customclassifier('url', 'wrong_method')
        thug.add_customclassifier('sample', self.sample_passthrough)
        thug.add_customclassifier('image', self.image_passthrough)
        thug.add_customclassifier('cookie', self.cookie_passthrough)

        with open(os.path.join(self.samples_path, sample), 'rb') as fd:
            data = fd.read()

        log.HTMLClassifier.classify(os.path.basename(sample), data)
        log.TextClassifier.classify(os.path.basename(sample), data)
        log.TextClassifier.classify(os.path.basename(sample), data)
        log.CookieClassifier.classify(os.path.basename(sample), data)
        log.CookieClassifier.classify(os.path.basename(sample), data)
        log.SampleClassifier.classify(data, hashlib.md5(data).hexdigest())
        log.ImageClassifier.classify('https://buffer.antifork.org/images/antifork.jpg', 'Antifork')
        log.ImageClassifier.classify('https://buffer.antifork.org/images/antifork.jpg', 'Antifork')

        log.HTMLClassifier.filter(os.path.basename(sample), data)
        log.JSClassifier.filter(os.path.basename(sample), data)
        log.VBSClassifier.filter(os.path.basename(sample), data)
        log.TextClassifier.filter(os.path.basename(sample), data)
        log.CookieClassifier.filter(os.path.basename(sample), data)
        log.SampleClassifier.filter(data, hashlib.md5(data).hexdigest())
        log.ImageClassifier.filter('https://buffer.antifork.org/images/antifork.jpg', 'Antifork')

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_html_classifier_1(self, caplog):
        sample   = os.path.join(self.samples_path, "test1.html")
        expected = ['[HTML Classifier] URL: test1.html (Rule: html_signature_1, Classification: strVar)']

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

    def test_sample_signature_10(self, caplog):
        sample   = os.path.join(self.test_files_path, "sample.exe")
        expected = ['[SAMPLE Classifier] URL: 52bfb8491cbf6c39d44d37d3c59ef406 (Rule: sample_signature_10, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_sample_filter_11(self, caplog):
        sample   = os.path.join(self.test_files_path, "sample.exe")
        expected = ['[SAMPLEFILTER Classifier] URL: 52bfb8491cbf6c39d44d37d3c59ef406 (Rule: sample_filter_11, Classification: )']

        self.do_perform_test(caplog, sample, expected)
