# Facebook Photo Uploader 4.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def SetExtractIptc(self, val):
    self.__dict__['ExtractIptc'] = val

    if len(val) > 255:
        log.warning('FaceBook PhotoUploader overflow in ExtractIptc property')

def SetExtractExif(self, val):
    self.__dict__['ExtractExif'] = val

    if len(val) > 255:
        log.warning('FaceBook PhotoUploader overflow in ExtractExif property')

