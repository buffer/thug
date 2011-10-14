# Ourgame GLWorld GLIEDown2.dll ActiveX Control Vulnerabilities

import logging
log = logging.getLogger("Thug.ActiveX")

def IEStartNative(self, arg0, arg1, arg2):
    if len(arg0) > 220:
        log.warning('GLWorld GLIEDown2.dll ActiveX IEStartNative Method Buffer Overflow')

