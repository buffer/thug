# Persists Software XUpload control, version 2.1.0.1.
# CVE-2007-6530

import logging
log = logging.getLogger("Thug.ActiveX")

def AddFolder(self, arg):
    if len(arg) > 1024:
        log.warning('XUpload ActiveX Overflow in AddFolder method')

def AddFile(self, arg):
    if len(arg) > 255: 
        log.warning('XUpload ActiveX Overflow in AddFile method')

