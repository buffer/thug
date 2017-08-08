# SonicWall SSL-VPN NetExtender NELaunchCtrl ActiveX control
# CVE-2007-5603 (AddRouteEntry)

import logging

log = logging.getLogger("Thug")


def AddRouteEntry(self, arg0, arg1):
    if len(arg0) > 20 or len(arg1) > 20:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "SonicWall SSL-VPN NetExtender NELaunchCtrl ActiveX",
                                          "Overflow in AddRouteEntry",
                                          cve = 'CVE-2007-5603')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-5603", None)
        log.DFT.check_shellcode(arg0)
        log.DFT.check_shellcode(arg1)
