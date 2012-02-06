# RTSP MPEG4 SP Control 1.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def SetMP4Prefix(self, val):
    self.__dict__['MP4Prefix'] = val

    if len(val) > 128:
        log.MAEC.add_behavior_warn('[RTSP MPEG4 SP Control ActiveX] Overflow in MP4Prefix property')

