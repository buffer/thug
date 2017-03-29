# Microsoft Internet Explorer 6 WebViewFolderIcon
# CVE-2006-3730

import logging

log = logging.getLogger("Thug")


def setSlice(self, arg0, arg1, arg2, arg3):
    log.ThugLogging.add_behavior_warn('[WebViewFolderIcon ActiveX] setSlice(%s, %s, %s, %s)' % (arg0, arg1, arg2, arg3, ))
    if arg0 == 0x7ffffffe:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "WebViewFolderIcon ActiveX",
                                          "setSlice attack",
                                          cve = 'CVE-2006-3730')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2006-3730", None)
