# Universal HTTP File Upload (UUploaderSverD.dll - v6.0.0.35)
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def RemoveFileOrDir(self, arg0, arg1): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Universal HTTP File Upload ActiveX] Deleting {arg0}')
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Universal HTTP File Upload ActiveX",
                                      "Deleting",
                                      data = {
                                                "filename": arg0
                                             },
                                      forward = False)
