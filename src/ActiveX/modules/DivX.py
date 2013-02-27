# DivX Player 6.6.0 ActiveX Control
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def SetPassword(self, arg0):
    if len(arg0) > 128:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "DivX Player ActiveX",
                                          "Overflow in SetPassword")
