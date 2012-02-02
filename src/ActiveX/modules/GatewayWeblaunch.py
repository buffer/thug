# Gateway Weblaunch ActiveX Control
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def DoWebLaunch(self, arg0, arg1, arg2, arg3):
    if len(arg1) > 512 or len(arg3) > 512:
        log.MAEC.add_behavior_warn('Gateway Weblaunch ActiveX overflow')
    else:
        log.MAEC.add_behavior_warn('Gateway Weblaunch ActiveX trying to execute ' + arg1 + ' ' + arg2 + ' ' + arg3)

