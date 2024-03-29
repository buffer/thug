# Yahoo! Messenger 8.x CYTF ActiveX Control

import logging

log = logging.getLogger("Thug")


def GetFile(self, url, local, arg2, arg3, cmd):  # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f"[Yahoo! Messenger 8.x CYTF] Downloading {url}")
    log.ThugLogging.log_exploit_event(
        self._window.url,
        "Yahoo! Messenger 8.x CYTF",
        "Downloading",
        forward=False,
        data={"url": url},
    )
