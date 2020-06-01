# WinZip FileView ActiveX Control
# CVE-2006-3890,CVE-2006-5198,CVE-2006-6884

import logging

log = logging.getLogger("Thug")


def CreateNewFolderFromName(self, arg):
    if len(arg) > 230:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "WinZip ActiveX",
                                          "CreateNewFolderFromName Overflow",
                                          cve = 'CVE-2006-6884')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2006-6884")
        log.DFT.check_shellcode(arg)
