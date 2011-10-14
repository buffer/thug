# iMesh<= 7.1.0.x IMWebControl Class
# CVE-2007-6493, CVE-2007-6492

import logging
log = logging.getLogger("Thug.ActiveX")

def ProcessRequestEx(self, arg):
    if len(arg) == 0:
        log.warning('IMWebControl NULL value in ProcessRequestEx()')

def SetHandler(self, arg):
    if str([arg]) == '218959117':
        log.warning('IMWebControl overflow in SetHandler()')
