# iMesh<= 7.1.0.x IMWebControl Class
# CVE-2007-6493, CVE-2007-6492

import logging
log = logging.getLogger("Thug")

def ProcessRequestEx(self, arg):
    if len(arg) == 0:
        log.MAEC.add_behavior_warn('IMWebControl NULL value in ProcessRequestEx',
                                   'CVE-2007-6492')

def SetHandler(self, arg):
    if str([arg]) == '218959117':
        log.MAEC.add_behavior_warn('IMWebControl overflow in SetHandler',
                                   'CVE-2007-6493')
