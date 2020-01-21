import os
import logging

import thug
from thug.ThugAPI.ThugOpts import ThugOpts
from thug.DOM.HTTPSession import HTTPSession
from thug.Logging.ThugLogging import ThugLogging
from thug.Classifier.URLClassifier import URLClassifier
from thug.Classifier.SampleClassifier import SampleClassifier

configuration_path = thug.__configuration_path__

log                    = logging.getLogger("Thug")
log.configuration_path = configuration_path
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None

log.ThugOpts         = ThugOpts()
log.HTTPSession      = HTTPSession()
log.URLClassifier    = URLClassifier()
log.SampleClassifier = SampleClassifier()

thug_logging = ThugLogging(thug.__version__)


class TestThugLogging:
    js       = "var i = 0;"
    cert     = "sample-certificate"
    content  = b"sample, content"
    cwd_path = os.path.dirname(os.path.realpath(__file__))
    jar_path = os.path.join(cwd_path, os.pardir, os.pardir, "tests/test_files/sample.jar")
    sample   = {'sha1': 'b13d13733c4c9406fd0e01485bc4a34170b7d326',
                'ssdeep': u'24:9EGtDqSyDVHNkCq4LOmvmuS+MfTAPxokCOB:97tG5DjQ4LDs+sTAPxLT',
                'sha256': '459bf0aeda19633c8e757c05ee06b8121a51217cea69ce60819bb34092a296a0',
                'type': 'JAR',
                'md5': 'd4be8fbeb3a219ec8c6c26ffe4033a16'}

    def test_set_url(self):
        thug_logging.set_url("https://www.example.com")
        assert thug_logging.url in ("https://www.example.com", )

    def test_add_code_snippet(self):
        log.ThugOpts.code_logging = False
        tag_hex = thug_logging.add_code_snippet(self.js, 'Javascript', 'Contained_Inside')
        assert not tag_hex

        log.ThugOpts.code_logging = True
        assert not thug_logging.add_code_snippet("var", 'Javascript', 'Contained', check = True)

        tag_hex = thug_logging.add_code_snippet(self.js, 'Javascript', 'Contained_Inside')
        assert tag_hex

    def test_add_shellcode_snippet(self):
        tag_hex = thug_logging.add_shellcode_snippet("sample", "Assembly", "Shellcode", "Static Analysis")
        assert tag_hex

    def test_log_file(self):
        sample = thug_logging.log_file(data = "")
        assert not sample

        data = open(self.jar_path, 'rb').read()
        sample = thug_logging.log_file(data = data, url = self.jar_path, sampletype = 'JAR')
        assert sample['sha1'] in ('b13d13733c4c9406fd0e01485bc4a34170b7d326', )

    def test_log_event(self, caplog):
        caplog.clear()
        log.ThugOpts.file_logging = True

        thug_logging.log_event()
        assert 'Thug analysis logs saved' in caplog.text

        log.ThugOpts.file_logging = False

    def test_log_connection(self):
        thug_logging.log_connection("referer", "url", "href")

    def test_log_location(self):
        thug_logging.log_location("https://example.com", None)

    def test_log_exploit_event(self, caplog):
        caplog.clear()

        thug_logging.log_exploit_event("https://www.example.com", "module", "sample-description")
        assert "[module] sample-description" in caplog.text

    def test_log_classifier(self, caplog):
        caplog.clear()

        thug_logging.log_classifier("sample", self.jar_path, "N/A", None)
        assert "[SAMPLE Classifier]" in caplog.text
        assert "(Rule: N/A, Classification: None)" in caplog.text

    def test_log_redirect(self, caplog):
        pass

    def test_log_href_direct(self, caplog):
        caplog.clear()

        thug_logging.log_href_redirect("referer", "url")
        assert "[HREF Redirection (document.location)]" in caplog.text
        assert "Content-Location: referer --> Location: url" in caplog.text

    def test_log_certificate(self, caplog):
        caplog.clear()
        log.ThugOpts.cert_logging = False
        thug_logging.log_certificate("url", self.cert)
        assert "[Certificate]" not in caplog.text

        log.ThugOpts.cert_logging = True
        thug_logging.log_certificate("url", self.cert)
        assert "%s" % (self.cert, ) in caplog.text

    def test_log_virustotal(self):
        log.ThugOpts.file_logging = True
        path = "%s.json" % (self.sample['md5'],)
        thug_logging.log_virustotal(os.getcwd(), self.sample, self.content)
        assert self.content in open(path, 'rb').read()

        os.remove(path)
        log.ThugOpts.file_logging = False

    def test_log_honeyagent(self):
        log.ThugOpts.file_logging = True
        path = "%s.json" % (self.sample['md5'], )
        thug_logging.log_honeyagent(os.getcwd(), self.sample, self.content)
        assert self.content in open(path, 'rb').read()

        os.remove(path)
        log.ThugOpts.file_logging = False

    def test_store_content(self):
        log.ThugOpts.file_logging = True
        fname = thug_logging.store_content(os.getcwd(), "sample.csv", self.content)
        path = os.path.join(os.getcwd(), "sample.csv")
        assert fname == path
        assert self.content in open(path, 'rb').read()

        os.remove(path)

        log.ThugOpts.file_logging = False
        fname = thug_logging.store_content(os.getcwd(), "sample.csv", self.content)
        assert not fname
