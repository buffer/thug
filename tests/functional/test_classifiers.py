import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestClassifiers(object):
    thug_path        = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    classifiers_path = os.path.join(thug_path, "thug", "samples/classifiers")
    signatures_path  = os.path.join(thug_path, "thug", "tests/signatures")

    def catchall(self, url, *args):
        log.warning("[CATCHALL Custom Classifier] URL: %s", url)

    def do_perform_remote_test(self, caplog, url, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_image_processing()
        thug.set_threshold(2)
        thug.disable_cert_logging()
        thug.set_features_logging()
        thug.set_ssl_verify()
        thug.log_init(url)

        thug.add_htmlclassifier(os.path.join(self.signatures_path, "html_signature_12.yar"))
        thug.add_imageclassifier(os.path.join(self.signatures_path, "image_signature_14.yar"))
        thug.add_imageclassifier(os.path.join(self.signatures_path, "image_signature_15.yar"))

        thug.run_remote(url)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()

        thug.set_useragent('winxpie70')
        thug.set_threshold(2)
        thug.disable_cert_logging()
        thug.set_features_logging()
        thug.set_ssl_verify()
        thug.log_init(sample)

        thug.reset_customclassifiers()
        thug.add_customclassifier('url', self.catchall)
        thug.reset_customclassifiers()
        thug.add_customclassifier('html', self.catchall)
        thug.add_customclassifier('url', self.catchall)
        thug.add_customclassifier('js', self.catchall)
        thug.add_customclassifier('vbs', self.catchall)
        thug.add_customclassifier('sample', self.catchall)
        thug.add_customclassifier('cookie', self.catchall)
        thug.add_customclassifier('text', self.catchall)

        thug.add_htmlclassifier(os.path.join(self.signatures_path, "html_signature_1.yar"))
        thug.add_jsclassifier(os.path.join(self.signatures_path, "js_signature_2.yar"))
        thug.add_urlclassifier(os.path.join(self.signatures_path, "url_signature_3.yar"))
        thug.add_urlfilter(os.path.join(self.signatures_path, "url_filter_4.yar"))
        thug.add_textclassifier(os.path.join(self.signatures_path, "text_signature_5.yar"))
        thug.add_vbsclassifier(os.path.join(self.signatures_path, "vbs_signature_6.yar"))
        thug.add_urlclassifier(os.path.join(self.signatures_path, "url_signature_7.yar"))
        thug.add_urlclassifier(os.path.join(self.signatures_path, "url_signature_13.yar"))

        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_html_classifier_1(self, caplog):
        sample   = os.path.join(self.classifiers_path, "test1.html")
        expected = ['[HTML Classifier]',
                    'thug/samples/classifiers/test1.html (Rule: html_signature_1, Classification: strVar)']

        self.do_perform_test(caplog, sample, expected)

    def test_js_classifier_2(self, caplog):
        sample   = os.path.join(self.classifiers_path, "test2.html")
        expected = ['[JS Classifier]',
                    'thug/samples/classifiers/test2.html (Rule: js_signature_2, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_url_classifier_3(self, caplog):
        sample   = os.path.join(self.classifiers_path, "test3.html")
        expected = ['[URL Classifier] URL: https://github.com/buffer/thug/ (Rule: url_signature_3, Classification: )',
                    '[CATCHALL Custom Classifier] URL: https://github.com/buffer/thug/']

        self.do_perform_test(caplog, sample, expected)

    def test_url_filter_4(self, caplog):
        sample   = os.path.join(self.classifiers_path, "test4.html")
        expected = ['[URLFILTER Classifier] URL: http://www.google.com (Rule: url_filter_4, Classification: )',
                    '[CATCHALL Custom Classifier] URL: http://www.google.com']

        self.do_perform_test(caplog, sample, expected)

    def test_text_signature_5(self, caplog):
        sample   = os.path.join(self.classifiers_path, "test5.html")
        expected = ['[TEXT Classifier]',
                    'thug/samples/classifiers/test5.html (Rule: text_signature_5, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_vbs_signature_6(self, caplog):
        sample   = os.path.join(self.classifiers_path, "test6.html")
        expected = ['[VBS Classifier]',
                    'thug/samples/classifiers/test6.html (Rule: vbs_signature_6, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_url_classifier_7(self, caplog):
        sample   = os.path.join(self.classifiers_path, "test7.html")
        expected = ['[discard_meta_domain_whitelist] Whitelisted domain: buffer.github.io',
                    '[CATCHALL Custom Classifier] URL: https://buffer.github.io/thug/']

        self.do_perform_test(caplog, sample, expected)

    def test_vbs_signature_8(self, caplog):
        sample   = os.path.join(self.classifiers_path, "test8.html")
        expected = ['[VBS Classifier]',
                    'thug/samples/classifiers/test8.html (Rule: vbs_signature_6, Classification: )']

        self.do_perform_test(caplog, sample, expected)

    def test_html_classifier_12(self, caplog):
        expected = ['[discard_meta_domain_whitelist] Whitelisted domain: antifork.org']

        self.do_perform_remote_test(caplog, 'buffer.antifork.org', expected)

    def test_url_classifier_13(self, caplog):
        sample   = os.path.join(self.classifiers_path, "test13.html")
        expected = ['[URL Classifier] URL: https://www.antifork.org/ (Rule: url_signature_13, Classification: antifork.org)']

        self.do_perform_test(caplog, sample, expected)

    def test_url_classifier_14(self, caplog):
        expected = ['[IMAGE Classifier] URL: https://buffer.antifork.org/images/antifork.jpg (Rule: image_signature_14, Classification: Antifork)',
                    '[discard_meta_domain_whitelist] Whitelisted domain: buffer.antifork.org (URL: https://buffer.antifork.org/images/antifork.jpg)']

        self.do_perform_remote_test(caplog, 'buffer.antifork.org', expected)
