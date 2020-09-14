# GOM Player GOM Manager ActiveX Control
# CVE-2007-5779

import logging

log = logging.getLogger("Thug")


def OpenURL(self, arg):
    if len(arg) > 500:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "GOM Player Manager ActiveX",
                                          "Overflow in OpenURL",
                                          cve = "CVE-2007-5779")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-5779")
        log.ThugLogging.Shellcode.check_shellcode(arg)
