import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestDisabledActiveX(object):
    thug_path = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    misc_path = os.path.join(thug_path, "thug", "samples/misc")

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.disable_acropdf()
        thug.disable_shockwave_flash()
        thug.disable_javaplugin()
        thug.disable_silverlight()

        thug.log_init(sample)
        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_disable_1(self, caplog):
        sample   = os.path.join(self.misc_path, "testObject6.html")
        expected = ['Unknown ActiveX Object: CA8A9780-280D-11CF-A24D-444553540000',
                    'Unknown ActiveX Object: 233C1507-6A77-46A4-9443-F871F945D258',
                    'Unknown ActiveX Object: CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA',
                    'Unknown ActiveX object: 1234']

        self.do_perform_test(caplog, sample, expected)

    def test_disable_2(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.9.1.html")
        expected = ['Unknown ActiveX Object: CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA',
                    'Unknown ActiveX Object: 5852F5ED-8BF4-11D4-A245-0080C6F74284']

        self.do_perform_test(caplog, sample, expected)
