# GOM Player GOM Manager ActiveX Control
# CVE-2007-5779

import logging
log = logging.getLogger("Thug")

def OpenURL(self, arg):
    if len(arg) > 500:
        log.MAEC.add_behavior_warn('GOM Player 2 overflow in OpenURL',
                                   'CVE-2007-5779')

