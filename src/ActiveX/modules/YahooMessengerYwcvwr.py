# Yahoo! Messenger 8.x Ywcvwr ActiveX Control
# CVE-2007-4391

import logging
log = logging.getLogger("Thug")

def Setserver(self, name):
    self.__dict__['server'] = name

    if len(name) > 255:
        log.ThugLogging.add_behavior_warn('[Yahoo! Messenger 8.x Ywcvwr ActiveX] Server Console Overflow',
                                   'CVE-2007-4391')

def GetComponentVersion(self, arg):
    log.ThugLogging.add_behavior_warn('[Yahoo! Messenger 8.x Ywcvwr ActiveX] GetComponentVersion Overflow',
                               'CVE-2007-4391')

def initialize(self):
    return

def send(self):
    return

def receive(self):
    return
