# DVRHOST Web CMS OCX 1.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def TimeSpanFormat(self, arg0, arg1):
    if len(arg1) > 512:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "DVRHOST Web CMS OCX ActiveX",
                                          "Overflow in TimeSpanFormat")
