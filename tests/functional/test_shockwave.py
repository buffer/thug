import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestShockwave(object):
    thug_path = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    misc_path = os.path.join(thug_path, "thug", "samples/misc")

    def do_perform_test(self, caplog, sample, shockwave, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_events('click,storage')
        thug.disable_cert_logging()
        thug.set_features_logging()
        
        if shockwave in ('disable', ):
            thug.disable_shockwave_flash()
        else:
            thug.set_shockwave_flash(shockwave)
        
        thug.log_init(sample)
        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_shockwave1(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.6.html")
        expected = ['AdobeReader version: 9.1.0.0',
                    'Flash version: 9.0.64.0']

        self.do_perform_test(caplog, sample, '9.0.64.0', expected)

    def test_shockwave2(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.6.html")
        expected = ['AdobeReader version: 9.1.0.0',
                    'Flash version: 10.0.64.0']

        self.do_perform_test(caplog, sample, '10.0.64.0', expected)

    def test_shockwave3(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.6.html")
        expected = ['AdobeReader version: 9.1.0.0',
                    'Flash version: 11.0.64.0']

        self.do_perform_test(caplog, sample, '11.0.64.0', expected)

    def test_shockwave4(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.6.html")
        expected = ['AdobeReader version: 9.1.0.0',
                    'Flash version: 12.0.64.0']

        self.do_perform_test(caplog, sample, '12.0.64.0', expected)

    def test_shockwave5(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.6.html")
        expected = ['AdobeReader version: 9.1.0.0', ]

        self.do_perform_test(caplog, sample, 'disable', expected)
