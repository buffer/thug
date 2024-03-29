# Multiple Office OCX ActiveX Controls 'OpenWebFile()' Arbitrary
# Program Execution Vulnerability
# BID-33243

import logging

log = logging.getLogger("Thug")


def OpenWebFile(self, _file):
    log.ThugLogging.add_behavior_warn(
        "[Office OCX ActiveX] OpenWebFile Arbitrary Program Execution Vulnerability"
    )
    log.ThugLogging.add_behavior_warn(f"[Office OCX ActiveX] Fetching from URL {_file}")
    log.ThugLogging.log_exploit_event(
        self._window.url,
        "Office OCX ActiveX",
        "OpenWebFile Arbitrary Program Execution Vulnerability (BID-33243)",
        forward=False,
        data={"url": _file},
    )

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "BID-33243")

    try:
        self._window._navigator.fetch(_file, redirect_type="Office OCX Exploit")
    except Exception:  # pylint:disable=broad-except
        log.ThugLogging.add_behavior_warn("[Office OCX ActiveX] Fetch failed")
