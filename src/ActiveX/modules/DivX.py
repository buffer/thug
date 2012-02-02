# DivX Player 6.6.0 ActiveX Control
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def SetPassword(self, arg0):
    if len(arg0) > 128:
        log.MAEC.add_behavior_warn('DivX overflow in SetPassword')
