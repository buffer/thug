# Vantage Linguistics AnserWorks ActiveX Controls
# CVE-2007-6387

import logging

log = logging.getLogger("Thug")


def GetHistory(self, arg):
    if len(arg) > 215:
        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6387")
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "AnswerWorks ActiveX",
                                          "Overflow in GetHistory",
                                          cve = 'CVE-2007-6387')
        log.ThugLogging.Shellcode.check_shellcode(arg)


def GetSeedQuery(self, arg):
    if len(arg) > 215:
        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6387")
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "AnswerWorks ActiveX",
                                          "Overflow in GetSeedQuery",
                                          cve = 'CVE-2007-6387')
        log.ThugLogging.Shellcode.check_shellcode(arg)


def SetSeedQuery(self, arg):
    if len(arg) > 215:
        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6387")
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "AnswerWorks ActiveX",
                                          "Overflow in SetSeedQuery",
                                          cve = 'CVE-2007-6387')
        log.ThugLogging.Shellcode.check_shellcode(arg)
