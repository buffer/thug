# Persists Software XUpload control, version 2.1.0.1.
# CVE-2007-6530

import logging

log = logging.getLogger("Thug")


def AddFolder(self, arg):
    if len(arg) > 1024:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "XUpload ActiveX",
                                          "Overflow in AddFolder method",
                                          cve = 'CVE-2007-6530')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6530")
        log.DFT.check_shellcode(arg)


def AddFile(self, arg):
    if len(arg) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "XUpload ActiveX",
                                          "Overflow in AddFile method",
                                          cve = 'CVE-2007-6530')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6530")
        log.DFT.check_shellcode(arg)
