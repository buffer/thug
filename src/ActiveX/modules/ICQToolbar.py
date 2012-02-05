# ICQ Toolbar attack
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def GetPropertyById(self, arg0, arg1):
    if len(arg1) > 120:
        log.MAEC.add_behavior_warn('ICQToolbar buffer overflow in GetPropertyById')
