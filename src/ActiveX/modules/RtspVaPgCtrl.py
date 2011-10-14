# RTSP MPEG4 SP Control 1.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def SetMP4Prefix(self, val):
    self.__dict__['MP4Prefix'] = val

    if len(val) > 128:
        log.warning('RTSP MPEG4 SP Control overflow in MP4Prefix property')

