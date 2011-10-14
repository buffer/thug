# MySpace Uploader Control 1.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def SetAction(self, val):
    self.__dict__['Action'] = val

    if len(val) > 512:
        log.warning('Myspace UPloader overflow in Action property')

