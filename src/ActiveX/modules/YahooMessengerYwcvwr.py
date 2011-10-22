# Yahoo! Messenger 8.x Ywcvwr ActiveX Control
# CVE-2007-4391

import logging
log = logging.getLogger("Thug.ActiveX")

def Setserver(self, name):
    self.__dict__['server'] = name

    if len(name) > 255:
        log.warning('Yahoo! Messenger ActiveX Server Console Overflow')

def GetComponentVersion(self, arg):
    log.warning('Yahoo! Messenger ActiveX GetComponentVersion Overflow')

def initialize(self):
    return

def send(self):
    return

def receive(self):
    return
