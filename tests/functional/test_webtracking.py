import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestWebTracking(object):
    thug_path = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    misc_path = os.path.join(thug_path, "thug", "samples/misc")

    def do_perform_test(self, caplog, url, expected, type_ = "remote"):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_events('click,storage')
        thug.set_web_tracking()
        thug.enable_cert_logging()
        thug.set_features_logging()
        thug.set_log_verbose()
        thug.set_ssl_verify()
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

    def test_sessionstorage(self, caplog):
        expected = ['[TRACKING] [[object Storage] setItem] key1 = value1',
                    '[TRACKING] [[object Storage] setItem] key2 = value2',
                    '[TRACKING] [[object Storage] setItem] key2 = value3',
                    '[TRACKING] [[object Storage] clear]',
                    '[TRACKING] [[object Storage] setItem] key123 = value123',
                    '[TRACKING] [[object Storage] removeItem] key123']

        sample = os.path.join(self.misc_path, "testSessionStorage.html")
        self.do_perform_test(caplog, sample, expected, "local")

    def test_bing(self, caplog):
        expected = ['Domain starting with initial dot: .bing.com']
        self.do_perform_test(caplog, "https://www.bing.com", expected)

    def test_github(self, caplog):
        expected = ['Secure flag set']
        self.do_perform_test(caplog, "http://www.github.com", expected)
