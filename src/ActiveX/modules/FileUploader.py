# Lycos FileUploader Module 2.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def SetHandwriterFilename(self, val):
    self.__dict__['HandwriterFilename'] = val

    if len(val) > 1024:
        log.ThugLogging.add_behavior_warn('[Lycos FileUploader ActiveX] Overflow in HandwriterFilename property')

