# Ourgame GLWorld GLIEDown2.dll ActiveX Control Vulnerabilities

import logging

log = logging.getLogger("Thug")


def IEStartNative(self, arg0, arg1, arg2):
    if len(arg0) > 220:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Ourgame GLWorld GLIEDown2.dll ActiveX",
                                          "IEStartNative Method Buffer Overflow")
