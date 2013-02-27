# Chinagames iGame CGAgent ActiveX Control Buffer Overflow
# CVE-2009-1800

import logging 
log = logging.getLogger("Thug")

def CreateChinagames(self, arg0):
    if len(arg0) > 428:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "CGAgent ActiveX",
                                          "CreateChinagames Method Buffer Overflow",
                                          cve = 'CVE-2009-1800')
