import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestPyHooks(object):
    cwd_path        = os.path.dirname(os.path.realpath(__file__))
    misc_path       = os.path.join(cwd_path, os.pardir, "samples/misc")
    exploits_path   = os.path.join(cwd_path, os.pardir, "samples/exploits")
    signatures_path = os.path.join(cwd_path, os.pardir, "signatures")

    def do_handle_params_hook(self, params):
        for name, value in params.items():
            log.warning("name = %s", name)
            log.warning("value = %s", value)

    def log_classifier_hook(self, classifier, url, rule, tags, meta):
        log.warning("Greetings from the hook")
        log.warning("classifier = %s", classifier)
        log.warning("url = %s", url)
        log.warning("rule = %s", rule)
        log.warning("tags = %s", tags)
        log.warning("meta = %s", meta)

    def do_perform_test(self, caplog, url, expected, type_ = "local"):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_features_logging()
        thug.set_ssl_verify()
        thug.set_connect_timeout(1)
        thug.add_urlclassifier(os.path.join(self.signatures_path, "url_signature_13.yar"))
        thug.register_pyhook("DFT", "do_handle_params", self.do_handle_params_hook)
        thug.register_pyhook("ThugLogging", "log_classifier", self.log_classifier_hook)
        thug.log_init(url)

        m = getattr(thug, "run_{}".format(type_))
        m(url)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_hook_1(self, caplog):
        expected = ['name = codebase',
                    'value = /external/examples/common/java/']

        sample = os.path.join(self.misc_path, "testObject2.html")
        self.do_perform_test(caplog, sample, expected, "local")

    def test_hook_2(self, caplog):
        expected = ['Greetings from the hook',
                    'classifier = exploit',
                    'rule = CVE-2007-0018']

        sample = os.path.join(self.exploits_path, "22196.html")
        self.do_perform_test(caplog, sample, expected, "local")

    def test_hook3(self, caplog):
        expected = ['Greetings from the hook',
                    'classifier = url',
                    'url = https://buffer.antifork.org',
                    'rule = url_signature_13']

        url = "https://buffer.antifork.org"
        self.do_perform_test(caplog, url, expected, "remote")
