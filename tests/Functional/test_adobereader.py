import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestAdobeReader(object):
    cwd_path  = os.path.dirname(os.path.realpath(__file__))
    misc_path = os.path.join(cwd_path, os.pardir, "samples/misc")

    def do_perform_test(self, caplog, sample, adobe, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_events('click,storage')
        thug.disable_cert_logging()
        thug.set_features_logging()

        if adobe in ('disable', ):
            thug.disable_acropdf()
        else:
            thug.set_acropdf_pdf(adobe)

        thug.log_init(sample)
        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_adobe1(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.6.html")
        expected = ['AdobeReader version: 9.1.0.0',
                    'Flash version: 10.0.64.0']

        self.do_perform_test(caplog, sample, '9.1.0.0', expected)

    def test_adobe2(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.6.html")
        expected = ['AdobeReader version: 10.1.0.0',
                    'Flash version: 10.0.64.0']

        self.do_perform_test(caplog, sample, '10.1.0.0', expected)

    def test_adobe3(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.6.html")
        expected = ['Flash version: 10.0.64.0', ]

        self.do_perform_test(caplog, sample, 'disable', expected)
