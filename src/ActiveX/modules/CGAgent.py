# Chinagames iGame CGAgent ActiveX Control Buffer Overflow
# CVE-2009-1800

import logging 
log = logging.getLogger("Thug")

def CreateChinagames(self, arg0):
    if len(arg0) > 428:
        log.MAEC.add_behavior_warn('CGAgent ActiveX CreateChinagames Method Buffer Overflow',
                                   'CVE-2009-1800')

