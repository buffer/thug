# jetAudio "DownloadFromMusicStore()" Arbitrary File Download Vulnerability
# CVE-2007-4983

import logging

log = logging.getLogger("Thug")


def DownloadFromMusicStore(self, url, dst, title, artist, album, genere, size, param1, param2): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[JetAudio ActiveX] Downloading from URL {url} (saving locally as {dst})')
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
    except Exception: # pylint:disable=broad-except
        log.ThugLogging.add_behavior_warn('[JetAudio ActiveX] Fetch failed')
