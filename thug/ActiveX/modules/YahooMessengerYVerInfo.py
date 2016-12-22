# Yahoo! Messenger 8.x YVerInfo.dll ActiveX Control
# CVE-2007-4515

import logging

log = logging.getLogger("Thug")


def fvcom(self, arg0):
    if len(arg0) > 20:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Yahoo! Messenger 8.x YVerInfo.dll ActiveX Control",
                                          "Overflow in fvCom arg0",
                                          cve = 'CVE-2007-4515')


def info(self, arg0):
    if len(arg0) > 20:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Yahoo! Messenger 8.x YVerInfo.dll ActiveX Control",
                                          "Overflow in info arg0",
                                          cve = 'CVE-2007-4515')
