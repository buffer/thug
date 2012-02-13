# Kingsoft Antivirus
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def SetUninstallName(self, arg):
    if len(arg) > 900:
        log.ThugLogging.add_behavior_warn('[Kingsoft AntiVirus ActiveX] SetUninstallName Heap Overflow')
