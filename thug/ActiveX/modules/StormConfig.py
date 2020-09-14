# BaoFeng Storm ActiveX Control SetAttributeValue() Buffer Overflow Vulnerability
# CVE-2009-1807

import logging

log = logging.getLogger("Thug")


def SetAttributeValue(self, arg0, arg1, arg2):
    if len(arg0) > 260:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "BaoFeng Storm ActiveX Control",
                                          "SetAttributeValue Buffer Overflow",
                                          cve = "CVE-2009-1807")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2009-1807")
        log.ThugLogging.Shellcode.check_shellcode(arg0)
