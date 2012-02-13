# D-Link MPEG4 SHM Audio Control
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def SetUrl(self, val):
    self.__dict__['Url'] = val
    if len(val) > 1024:
        log.ThugLogging.add_behavior_warn('[D-Link MPEG4 SHM Audio Control ActiveX] Overflow in Url property')


