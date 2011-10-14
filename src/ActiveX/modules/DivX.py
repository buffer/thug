# DivX Player 6.6.0 ActiveX Control
# CVE-NOMATCHd

import logging
log = logging.getLogger("Thug.ActiveX")

def SetPassword(self, arg0):
    if len(arg0) > 128:
        log.warning('DivX overflow in SetPassword');
