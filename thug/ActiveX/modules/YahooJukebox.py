# Yahoo! Music Jukebox 2.x
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def AddBitmap(self, arg0, arg1, arg2, arg3, arg4, arg5):
    if len(arg1) > 256:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Yahoo! Music Jukebox ActiveX",
                                          "Overflow in AddBitmap")
        log.DFT.check_shellcode(arg1)


def AddButton(self, arg0, arg1):
    if len(arg0) > 256:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Yahoo! Music Jukebox ActiveX",
                                          "Overflow in AddButton")
        log.DFT.check_shellcode(arg0)


def AddImage(self, arg0, arg1):
    if len(arg0) > 256:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Yahoo! Music Jukebox ActiveX",
                                          "Overflow in AddImage")
        log.DFT.check_shellcode(arg0)
