# VLC ActiveX Control
# CVE-2007-4619, CVE-2007-6262

import logging
log = logging.getLogger("Thug")

def getVariable(self, arg):
    if len(arg) > 255:
        log.MAEC.add_behavior_warn('[VLC ActiveX] getVariable Overflow',
                                   'CVE-2007-6262')

def setVariable(self, arg0, arg1):
    if len(arg0) > 255 or len(arg1) > 255:
        log.MAEC.add_behavior_warn('[VLC ActiveX] setVariable Overflow',
                                   'CVE-2007-6262')

def addTarget(self, arg0, arg1, arg2, arg3):
    if len(arg0) > 255 or len(arg1) > 255 or len(arg2) > 255 or len(arg3) > 255:
        log.MAEC.add_behavior_warn('[VLC ActiveX] addTarget Overflow',
                                   'CVE-2007-6262')

