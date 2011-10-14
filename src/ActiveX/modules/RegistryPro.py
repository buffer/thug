# Registry Pro (epRegPro.ocx)
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def DeleteKey(self, arg0, arg1):
    if arg0 in (80000001, 80000002, ):
        log.warning('RegistryPro ActiveX deleting [HKEY_LOCAL_MACHINE/%s]' % (arg1, ))
	
def About(self):
    log.warning('RegistryPro ActiveX About called')
