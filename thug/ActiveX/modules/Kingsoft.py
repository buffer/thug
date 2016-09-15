# Kingsoft Antivirus
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def SetUninstallName(self, arg):
    if len(arg) > 900:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Kingsoft AntiVirus ActiveX",
                                          "SetUninstallName Heap Overflow")
