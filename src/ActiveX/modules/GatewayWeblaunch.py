# Gateway Weblaunch ActiveX Control
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def DoWebLaunch(self, arg0, arg1, arg2, arg3):
    if len(arg1) > 512 or len(arg3) > 512:
        log.warning('GatewayWeblaunch overflow')
    else:
        log.warning('GatewayWeblaunch is trying to execute '+ arg1 + ' ' + arg2 + ' ' + arg3)

