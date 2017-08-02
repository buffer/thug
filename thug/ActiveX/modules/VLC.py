# VLC ActiveX Control
# CVE-2007-4619, CVE-2007-6262

import logging

log = logging.getLogger("Thug")


def getVariable(self, arg):
    if len(arg) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "VLC ActiveX",
                                          "getVariable Overflow",
                                          cve = "CVE-2007-6262")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6262", None)
        log.DFT.check_shellcode(arg)


def setVariable(self, arg0, arg1):
    if len(arg0) > 255 or len(arg1) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "VLC ActiveX",
                                          "setVariable Overflow",
                                          cve = "CVE-2007-6262")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6262", None)
        log.DFT.check_shellcode(arg0)
        log.DFT.check_shellcode(arg1)


def addTarget(self, arg0, arg1, arg2, arg3):
    if len(arg0) > 255 or len(arg1) > 255 or len(arg2) > 255 or len(arg3) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "VLC ActiveX",
                                          "addTarget Overflow",
                                          cve = "CVE-2007-6262")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6262", None)
        log.DFT.check_shellcode(arg0)
        log.DFT.check_shellcode(arg1)
        log.DFT.check_shellcode(arg2)
        log.DFT.check_shellcode(arg3)
