# Lycos FileUploader Module 2.x
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def SetHandwriterFilename(self, val):
    self.__dict__['HandwriterFilename'] = val

    if len(val) > 1024:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Lycos FileUploader ActiveX",
                                          "Overflow in HandwriterFilename property")
        log.DFT.check_shellcode(val)
