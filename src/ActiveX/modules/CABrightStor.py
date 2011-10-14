# CA BrightStor
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def AddColumn(self, arg0, arg1):
    if len(arg0) > 100:
        log.warning('CA BrightStor overflow in AddColumn()')
