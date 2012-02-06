# Yahoo! Music Jukebox 2.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def AddBitmap(self, arg0, arg1, arg2, arg3, arg4, arg5):
    if len(arg1) > 256:
        log.MAEC.add_behavior_warn('[Yahoo! Music Jukebox ActiveX] Overflow in AddBitmap')

def AddButton(self, arg0, arg1):
    if len(arg0) > 256:
        log.MAEC.add_behavior_warn('[Yahoo! Music Jukebox ActiveX] Overflow in AddButton')

def AddImage(self, arg0, arg1):
    if len(arg0) > 256:
        log.MAEC.add_behavior_warn('[Yahoo! Music Jukebox ActiveX] Overflow in AddImage')

