# Gateway Weblaunch ActiveX Control
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def DoWebLaunch(self, arg0, arg1, arg2, arg3):
    if len(arg1) > 512 or len(arg3) > 512:
        log.ThugLogging.add_behavior_warn('[Gateway Weblaunch ActiveX] Overflow')
    else:
        log.ThugLogging.add_behavior_warn('[Gateway Weblaunch ActiveX] Trying to execute ' + arg1 + ' ' + arg2 + ' ' + arg3)

