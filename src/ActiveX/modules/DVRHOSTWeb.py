# DVRHOST Web CMS OCX 1.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def TimeSpanFormat(self, arg0, arg1):
    if len(arg1) > 512:
        log.warning('DVRHOST Web CMS OCX Overflow in TimeSpanFormat')

