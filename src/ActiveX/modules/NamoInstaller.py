# NamoInstaller ActiveX Control 1.x - 3.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def Install(self, arg):
    if str([arg]).find('http') > -1:
        log.warning('NamoInstaller ActiveX insecure download (%s)' % (arg, ))

    if len(arg) > 1024:
        log.warning('NamoInstaller ActiveX Overflow in Install')
