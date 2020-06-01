# Microsoft Windows Media Encoder WMEX.DLL ActiveX BufferOverflow vulnerability
# CVE-2008-3008

import logging

log = logging.getLogger("Thug")


def GetDetailsString(self, arg0, arg1):
    if len(arg0) > 1023:
        log.ThugLogging.add_behavior_warn('[Microsoft Windows Media Encoder WMEX.DLL ActiveX] GetDetailsString Method Buffer Overflow',
                                          'CVE-2008-3008')
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Microsoft Windows Media Encoder WMEX.DLL ActiveX",
                                          "GetDetailsString Method Buffer Overflow",
                                          cve = "CVE-2008-3008")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2008-3008")
        log.DFT.check_shellcode(arg0)
