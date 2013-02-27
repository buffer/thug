# Move Networks Upgrade Manager 1.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def Upgrade(self, arg0, arg1, arg2, arg3):
    if len(arg0) > 6000:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Move Networks Upgrade Manager ActiveX",
                                          "Overflow in Upgrade")
