# Qvod Player QvodCtrl Class ActiveX Control
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def SetURL(self, val):
    self.__dict__['URL'] = val
    self.__dict__['url'] = val

    if len(val) > 800:
        log.MAEC.add_behavior_warn('[Qvod Player QvodCtrl Class ActiveX] Overflow in URL property')

