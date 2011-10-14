# WinZip FileView ActiveX Control
# CVE-2006-3890,CVE-2006-5198,CVE-2006-6884

import logging
log = logging.getLogger("Thug.ActiveX")

def CreateNewFolderFromName(self, arg):
    if len(arg) > 230:
        log.warning('WinZip ActiveX CreateNewFolderFromName Overflow')
