# Lycos FileUploader Module 2.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def SetHandwriterFilename(self, val):
    self.__dict__['HandwriterFilename'] = val

    if len(val) > 1024:
        log.warning('FileUploader ActiveX overflow in HandwriterFilename property')

