# MySpace Uploader Control 1.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def SetAction(self, val):
    self.__dict__['Action'] = val

    if len(val) > 512:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Myspace UPloader ActiveX",
                                          "Overflow in Action property")
