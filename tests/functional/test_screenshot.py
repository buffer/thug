import os
import logging

import pytest

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")

IN_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true" and os.getenv(
    "RUNNER_OS"
) in ("Linux",)


class TestScreenshot(object):
    def do_perform_test(self, caplog, url, expected, type_="remote"):
        thug = ThugAPI()

        thug.set_useragent("win7ie90")
        thug.disable_screenshot()
        thug.enable_screenshot()
        thug.set_file_logging()
        thug.set_json_logging()
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

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_antifork(self, caplog):
        expected = []
        self.do_perform_test(caplog, "https://buffer.antifork.org", expected)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_invalid_ctype(self, caplog):
        expected = []
        self.do_perform_test(
            caplog, "https://buffer.antifork.org/images/antifork.jpg", expected
        )
