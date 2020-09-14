# Ourgame GLWorld HanGamePluginCn18 Class ActiveX Control
# CVE-2008-0647

import logging

log = logging.getLogger("Thug")


def hgs_startGame(self, arg):
    if len(arg) > 1000:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Ourgame GLWorld ActiveX",
                                          "Overflow in hgs_startGame",
                                          cve = 'CVE-2008-0647')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2008-0647")
        log.ThugLogging.Shellcode.check_shellcode(arg)


def hgs_startNotify(self, arg):
    if len(arg) > 1000:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Ourgame GLWorld ActiveX",
                                          "Overflow in hgs_startNotify",
                                          cve = 'CVE-2008-0647')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2008-0647")
        log.ThugLogging.Shellcode.check_shellcode(arg)
