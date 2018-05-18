# iMesh<= 7.1.0.x IMWebControl Class
# CVE-2007-6493, CVE-2007-6492

import logging

log = logging.getLogger("Thug")


def ProcessRequestEx(self, arg):
    if not arg:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "iMesh IMWebControl ActiveX",
                                          "NULL value in ProcessRequestEx",
                                          cve = 'CVE-2007-6492')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6492", None)


def SetHandler(self, arg):
    if str([arg]) == '218959117':
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "iMesh IMWebControl ActiveX",
                                          "Overflow in SetHandler",
                                          cve = 'CVE-2007-6493')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6493", None)
