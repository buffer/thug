# AOL Radio AOLMediaPlaybackControl.exe
# CVE-2007-6250

import logging

log = logging.getLogger("Thug")


def AppendFileToPlayList(self, arg):
    if len(arg) > 512:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "AOL Radio AOLMediaPlaybackControl ActiveX",
                                          "Overflow in AppendFileToPlayList",
                                          cve = 'CVE-2007-6250')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6250", None)


def ConvertFile(self, *arg):
    # FIXME
    if len(arg[0]) > 512:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "AOL Radio AOLMediaPlaybackControl ActiveX",
                                          "Overflow in ConvertFile",
                                          cve = 'CVE-2007-6250')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6250", None)
