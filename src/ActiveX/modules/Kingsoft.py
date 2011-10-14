# Kingsoft Antivirus
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def SetUninstallName(self, arg):
    if len(arg) > 900:
        log.warning('Kingsoft SetUninstallName Heap Overflow')
