# Persists Software XUpload control, version 2.1.0.1.
# CVE-2007-6530

import logging
log = logging.getLogger("Thug")

def AddFolder(self, arg):
    if len(arg) > 1024:
        log.ThugLogging.add_behavior_warn('[XUpload ActiveX] Overflow in AddFolder method',
                                   'CVE-2007-6530')

def AddFile(self, arg):
    if len(arg) > 255: 
        log.ThugLogging.add_behavior_warn('[XUpload ActiveX] Overflow in AddFile method',
                                   'CVE-2007-6530')

