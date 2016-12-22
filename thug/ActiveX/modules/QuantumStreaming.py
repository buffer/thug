# Move Networks Quantum Streaming Player Control
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def UploadLogs(self, url, arg):
    if len(url) > 20000:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Move Networks Quantum Streaming Player Control ActiveX",
                                          "Overflow in UploadLogs method")
