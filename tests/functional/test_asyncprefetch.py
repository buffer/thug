import os
import logging

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestAsyncPrefetch:
    cwd_path  = os.path.dirname(os.path.realpath(__file__))
    misc_path = os.path.join(cwd_path, os.pardir, "samples/misc")

    def do_perform_test(self, caplog, url, expected, type_ = "remote"):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_events('click,storage')
        thug.set_web_tracking()
        thug.enable_cert_logging()
        thug.set_features_logging()
        thug.set_log_verbose()
        thug.set_ssl_verify()
        thug.get_async_prefetch()
        thug.reset_async_prefetch()
        thug.get_async_prefetch()
        thug.set_async_prefetch()
        thug.log_init(url)

        m = getattr(thug, f"run_{type_}")
        m(url)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_async_prefetch_1(self, caplog):
        expected = ["PREFETCHING", ]
        self.do_perform_test(caplog, "https://www.verizon.com", expected)
