import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestExtensive(object):
    cwd_path  = os.path.dirname(os.path.realpath(__file__))
    misc_path = os.path.join(cwd_path, os.pardir, "samples/misc")

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_events('click,storage')
        thug.set_extensive()
        thug.disable_cert_logging()
        thug.set_file_logging()
        thug.set_json_logging()
        thug.set_features_logging()
        thug.set_ssl_verify()
        thug.set_threshold(3)
        thug.log_init(sample)
        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_Anchor1(self, caplog):
        sample   = os.path.join(self.misc_path, "testAnchor1.html")
        expected = ["[anchor redirection]", ]

        self.do_perform_test(caplog, sample, expected)

    def test_Anchor2(self, caplog):
        sample   = os.path.join(self.misc_path, "testAnchor2.html")
        expected = ["[anchor redirection]", ]

        self.do_perform_test(caplog, sample, expected)

    def test_Anchor3(self, caplog):
        sample   = os.path.join(self.misc_path, "testAnchor3.html")
        expected = ["Hello world", ]

        self.do_perform_test(caplog, sample, expected)

    def test_Anchor4(self, caplog):
        sample   = os.path.join(self.misc_path, "testAnchor4.html")
        expected = ["Hello world", ]

        self.do_perform_test(caplog, sample, expected)

    def test_Anchor5(self, caplog):
        sample   = os.path.join(self.misc_path, "testAnchor5.html")
        expected = ["testAnchor5 success", ]

        self.do_perform_test(caplog, sample, expected)

    def test_Anchor6(self, caplog):
        sample   = os.path.join(self.misc_path, "testAnchor6.html")
        expected = ["testAnchor5 success", ]

        self.do_perform_test(caplog, sample, expected)

    def test_Anchor7(self, caplog):
        sample   = os.path.join(self.misc_path, "testAnchor7.html")
        expected = ["[MIMEHandler] Unknown MIME Type: application/font-woff2", ]

        self.do_perform_test(caplog, sample, expected)

    def test_Anchors1(self, caplog):
        sample   = os.path.join(self.misc_path, "testAnchors1.html")
        expected = ["[window open redirection] about:blank -> https://buffer.antifork.org/westwood/westwood.html",
                    "[document.write] Deobfuscated argument: <a href=\"https://buffer.antifork.org/westwood/westwood.html\">Antifork Research</a>", ]

        self.do_perform_test(caplog, sample, expected)

    def test_Anchors2(self, caplog):
        sample   = os.path.join(self.misc_path, "testAnchors2.html")
        expected = ["[document.write] Deobfuscated argument: <a>Google</a>", ]

        self.do_perform_test(caplog, sample, expected)

    def test_Anchors3(self, caplog):
        sample   = os.path.join(self.misc_path, "testAnchors3.html")
        expected = ["[window open redirection] about:blank -> https://buffer.antifork.org/westwood/westwood.html", ]

        self.do_perform_test(caplog, sample, expected)
