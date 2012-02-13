# Facebook Photo Uploader 4.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def SetExtractIptc(self, val):
    self.__dict__['ExtractIptc'] = val

    if len(val) > 255:
        log.ThugLogging.add_behavior_warn('[FaceBook Photo Uploader ActiveX] Overflow in ExtractIptc property')

def SetExtractExif(self, val):
    self.__dict__['ExtractExif'] = val

    if len(val) > 255:
        log.ThugLogging.add_behavior_warn('[FaceBook Photo Uploader ActiveX] Overflow in ExtractExif property')

