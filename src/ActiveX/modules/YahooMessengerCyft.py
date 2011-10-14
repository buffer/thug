# Yahoo! Messenger 8.x CYTF ActiveX Control

import logging
log = logging.getLogger("Thug.ActiveX")

def GetFile(self, url, local, arg2, arg3, cmd):
    log.warning('Yahoo! Messenger 8.x CYTF downloading %s' % (url, ))
