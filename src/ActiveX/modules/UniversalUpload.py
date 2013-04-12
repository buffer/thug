# Universal HTTP File Upload (UUploaderSverD.dll - v6.0.0.35)
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def RemoveFileOrDir(self, arg0, arg1):
    log.ThugLogging.add_behavior_warn('[Universal HTTP File Upload ActiveX] Deleting %s' % (arg0, ))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Universal HTTP File Upload ActiveX",
                                      "Deleting",
                                      data = {
                                                "filename": arg0
                                             },
                                      forward = False)
