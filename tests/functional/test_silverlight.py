import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestSilverLight(object):
    thug_path = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    misc_path = os.path.join(thug_path, "thug", "samples/misc")

    def do_perform_test(self, caplog, sample, silverlight, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_events('click,storage')
        thug.disable_cert_logging()
        thug.set_features_logging()
        
        if silverlight in ('disable', ):
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

    def test_silverlight1(self, caplog):
        sample   = os.path.join(self.misc_path, "testSilverLight.html")
        expected = ['Unknown ActiveX Object: agcontrol.agcontrol', ]

        self.do_perform_test(caplog, sample, 'disable', expected)
