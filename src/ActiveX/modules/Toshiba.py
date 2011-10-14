# Toshiba Surveillance (Surveillix) RecordSend Class (MeIpCamX.DLL 1.0.0.4)
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def SetPort(self, arg):
    if len(arg) > 10:
        log.warning('Toshiba Surveillance ActiveX Overflow in SetPort')

def SetIpAddress(self, arg):
    if len(arg) > 18:
        log.warning('Toshiba Surveillance ActiveX Overflow in SetIpAddress')

