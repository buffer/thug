# ICQ Toolbar attack
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def GetPropertyById(self, arg0, arg1):
    if len(arg1) > 120:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "ICQ Toolbar ActiveX",
                                          "Buffer overflow in GetPropertyById")
