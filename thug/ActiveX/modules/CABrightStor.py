# CA BrightStor
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def AddColumn(self, arg0, arg1):
    if len(arg0) > 100:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "CA BrightStor ActiveX",
                                          "Overflow in AddColumn")
