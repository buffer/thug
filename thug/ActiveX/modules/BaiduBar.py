# BaiduBar.dll ActiveX DloadDS() Remote Code Execution Vulnerability
# BUGTRAQ  ID: 25121

import logging

log = logging.getLogger("Thug")


def DloadDS(self, arg0, arg1, arg2):
    if str(arg0).lower().find(".cab") != -1:
        log.ThugLogging.add_behavior_warn('[BaiduBar.dll ActiveX] DloadDS function trying to download %s' % (arg0, ))
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "BaiduBar.dll ActiveX",
                                          "DloadDS function trying to download",
                                          data = {
                                                    "url": arg0
                                                 },
                                          forward = False)
