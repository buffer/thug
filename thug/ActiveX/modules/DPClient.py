# Xunlei DPClient.Vod.1 ActiveX Control DownURL2 Method Remote Buffer Overflow Vulnerability
# CVE-2007-5064

import logging

log = logging.getLogger("Thug")


def DownURL2(self, arg0, *args):
    if len(arg0) > 1024:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Xunlei DPClient.Vod.1 ActiveX",
                                          "DownURL2 Method Buffer Overflow",
                                          cve = "CVE-2007-5064")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-5064")
        log.DFT.check_shellcode(arg0)
