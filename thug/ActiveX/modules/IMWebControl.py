# iMesh<= 7.1.0.x IMWebControl Class
# CVE-2007-6493, CVE-2007-6492

import logging
log = logging.getLogger("Thug")

def ProcessRequestEx(self, arg):
    if len(arg) == 0:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "iMesh IMWebControl ActiveX",
                                          "NULL value in ProcessRequestEx",
                                          cve = 'CVE-2007-6492')

def SetHandler(self, arg):
    if str([arg]) == '218959117':
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "iMesh IMWebControl ActiveX",
                                          "Overflow in SetHandler",
                                          cve = 'CVE-2007-6493')
