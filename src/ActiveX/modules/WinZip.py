# WinZip FileView ActiveX Control
# CVE-2006-3890,CVE-2006-5198,CVE-2006-6884

import logging
log = logging.getLogger("Thug")

def CreateNewFolderFromName(self, arg):
    if len(arg) > 230:
        log.ThugLogging.add_behavior_warn('[WinZip ActiveX] CreateNewFolderFromName Overflow',
                                   'CVE-2006-6884')
