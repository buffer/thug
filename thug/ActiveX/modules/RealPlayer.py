# RealMedia RealPlayer Ierpplug.DLL ActiveX Control
# CVE-2007-5601

import logging

log = logging.getLogger("Thug")


def DoAutoUpdateRequest(self, arg0, arg1, arg2):
    if len(arg0) >= 32 or len(arg1) >= 32:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "RealMedia RealPlayer Ierpplug.DLL ActiveX",
                                          "Overflow in DoAutoUpdateRequest",
                                          cve = "CVE-2007-5601")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-5601", None)
        log.DFT.check_shellcode(arg0)
        log.DFT.check_shellcode(arg1)


def PlayerProperty(self, arg):
    if arg == 'PRODUCTVERSION':
        return '6.0.14.552'

    if len(arg) > 1000:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "RealMedia RealPlayer Ierpplug.DLL ActiveX",
                                          "Overflow in PlayerProperty",
                                          cve = "CVE-2007-5601")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-5601", None)
        log.DFT.check_shellcode(arg)


def Import(self, arg):
    if len(arg) > 0x8000:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "RealMedia RealPlayer Ierpplug.DLL ActiveX",
                                          "Overflow in Import",
                                          cve = "CVE-2007-5601")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-5601", None)
        log.DFT.check_shellcode(arg)


def SetConsole(self, val):
    self.__dict__['Console'] = val

    if len(val) >= 32:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "RealMedia RealPlayer rmoc3260.DLL ActiveX",
                                          "Overflow in Console property",
                                          cve = "CVE-2007-5601")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-5601", None)
        log.DFT.check_shellcode(val)
