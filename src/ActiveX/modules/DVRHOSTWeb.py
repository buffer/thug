# DVRHOST Web CMS OCX 1.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def TimeSpanFormat(self, arg0, arg1):
    if len(arg1) > 512:
        log.ThugLogging.add_behavior_warn('[DVRHOST Web CMS OCX ActiveX] Overflow in TimeSpanFormat')

