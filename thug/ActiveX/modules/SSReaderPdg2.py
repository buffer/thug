# SSReader Pdg2 ActiveX control (pdg2.dll)
# CVE-2007-5892

import logging

log = logging.getLogger("Thug")


def Register(self, arg0, arg1):
    if len(arg1) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "SSReader Pdg2 ActiveX",
                                          "Register Method Overflow",
                                          cve = "CVE-2007-5892")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-5892", None)
        log.DFT.check_shellcode(arg1)


def LoadPage(self, arg0, arg1, arg2, arg3):
    if len(arg0) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "SSReader Pdg2 ActiveX",
                                          "LoadPage Method Overflow",
                                          cve = "CVE-2007-5892")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-5892", None)
        log.DFT.check_shellcode(arg0)
