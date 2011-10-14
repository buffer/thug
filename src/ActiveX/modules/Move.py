# Move Networks Upgrade Manager 1.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def Upgrade(self, arg0, arg1, arg2, arg3):
    if len(arg0) > 6000:
        log.warning('Move Networks Upgrade Manager ActiveX Overflow in Upgrade')

