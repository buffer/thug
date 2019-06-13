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
                    'Unknown ActiveX object: agcontrol.agcontrol',
                    'Unknown ActiveX object: javaplugin',
                    'Unknown ActiveX object: JavaWebStart.isInstalled.1.7.0.0']

        self.do_perform_test(caplog, sample, expected)
