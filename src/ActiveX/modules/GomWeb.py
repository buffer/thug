# GOM Player GOM Manager ActiveX Control
# CVE-2007-5779

import logging
log = logging.getLogger("Thug.ActiveX")

def OpenURL(self, arg):
    if len(arg) > 500:
        log.warning('GOM Player 2 overflow in OpenURL')

