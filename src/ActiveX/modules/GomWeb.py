# GOM Player GOM Manager ActiveX Control
# CVE-2007-5779

import logging
log = logging.getLogger("Thug")

def OpenURL(self, arg):
    if len(arg) > 500:
        log.ThugLogging.add_behavior_warn('[GOM Player Manager ActiveX] Overflow in OpenURL',
                                   'CVE-2007-5779')

