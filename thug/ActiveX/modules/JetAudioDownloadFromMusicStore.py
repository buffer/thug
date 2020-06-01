# jetAudio "DownloadFromMusicStore()" Arbitrary File Download Vulnerability
# CVE-2007-4983

import logging

log = logging.getLogger("Thug")


def DownloadFromMusicStore(self, url, dst, title, artist, album, genere, size, param1, param2):
    log.ThugLogging.add_behavior_warn('[JetAudio ActiveX] Downloading from URL %s (saving locally as %s)' % (url, dst, ))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "JetAudio ActiveX",
                                      "Downloading from URL",
                                      cve = "CVE-2007-4983",
                                      data = {
                                                "url" : url,
                                                "file": dst
                                             },
                                      forward = False)

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-4983")

    try:
        self._window._navigator.fetch(url, redirect_type = "JetAudio exploit")
    except Exception:
        log.ThugLogging.add_behavior_warn('[JetAudio ActiveX] Fetch failed')
