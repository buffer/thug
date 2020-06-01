# BitDefender Online Scanner ActiveX Control
# CVE-2007-5775

import logging

log = logging.getLogger("Thug")


def initx(self, arg):
    if len(arg) > 1024:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "BitDefender Online Scanner ActiveX",
                                          "InitX overflow",
                                          cve = "CVE-2007-5775")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-5775")
        log.DFT.check_shellcode(arg)
