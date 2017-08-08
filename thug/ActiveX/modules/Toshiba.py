# Toshiba Surveillance (Surveillix) RecordSend Class (MeIpCamX.DLL 1.0.0.4)
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def SetPort(self, arg):
    if len(arg) > 10:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Toshiba Surveillance RecordSend Class ActiveX",
                                          "Overflow in SetPort")
        log.DFT.check_shellcode(arg)


def SetIpAddress(self, arg):
    if len(arg) > 18:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Toshiba Surveillance RecordSend Class ActiveX",
                                          "Overflow in SetIpAddress")
        log.DFT.check_shellcode(arg)
