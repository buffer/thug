# ICQ Toolbar attack
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def GetPropertyById(self, arg0, arg1):
    if len(arg1) > 120:
        log.warning('ICQToolbar buffer overflow in GetPropertyById')
