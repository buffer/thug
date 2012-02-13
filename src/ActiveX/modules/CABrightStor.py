# CA BrightStor
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def AddColumn(self, arg0, arg1):
    if len(arg0) > 100:
        log.ThugLogging.add_behavior_warn('[CA BrightStor ActiveX] Overflow in AddColumn')
