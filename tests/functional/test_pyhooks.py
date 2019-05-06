import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestPyHooks(object):
    thug_path = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    misc_path = os.path.join(thug_path, "thug", "samples/misc")

    def do_handle_params_hook(self, params):
        for name, value in params.items():
            log.warning("name = %s", name)
            log.warning("value = %s", value)

    def do_perform_test(self, caplog, url, expected, type_ = "local"):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_features_logging()
        thug.set_connect_timeout(1)
        thug.log_init(url)
        thug.register_pyhook("DFT", "do_handle_params", self.do_handle_params_hook)

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
