# Registry Pro (epRegPro.ocx)
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def DeleteKey(self, arg0, arg1):
    if arg0 in (80000001, 80000002, ):
        log.ThugLogging.add_behavior_warn('[RegistryPro ActiveX] Deleting [HKEY_LOCAL_MACHINE/%s]' % (arg1, ))
	
def About(self):
    log.ThugLogging.add_behavior_warn('[RegistryPro ActiveX] About called')
