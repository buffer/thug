# Yahoo! Messenger 8.x Ywcvwr ActiveX Control
# CVE-2007-4391

import logging
log = logging.getLogger("Thug")

def Setserver(self, name):
    self.__dict__['server'] = name

    if len(name) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Yahoo! Messenger 8.x Ywcvwr ActiveX",
                                          "Server Console Overflow",
                                          cve = "CVE-2007-4391")

def GetComponentVersion(self, arg):
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Yahoo! Messenger 8.x Ywcvwr ActiveX",
                                      "GetComponentVersion Overflow",
                                      cve = "CVE-2007-4391")

def initialize(self):
    return

def send(self):
    return

def receive(self):
    return
