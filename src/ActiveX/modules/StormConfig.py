# BaoFeng Storm ActiveX Control SetAttributeValue() Buffer Overflow Vulnerability
# CVE-2009-1807

import logging
log = logging.getLogger("Thug")

def SetAttributeValue(self, arg0, arg1, arg2):
    if len(arg0) > 260:
        log.MAEC.add_behavior_warn('[BaoFeng Storm ActiveX Control] SetAttributeValue Buffer Overflow',
                                   'CVE-2009-1807')
