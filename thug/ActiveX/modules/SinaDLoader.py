# Sina DLoader Class ActiveX Control 'DonwloadAndInstall'
# Method Arbitrary File Download Vulnerability

import logging

log = logging.getLogger("Thug")


def DownloadAndInstall(self, url):
    log.ThugLogging.add_behavior_warn(f"[SinaDLoader Downloader ActiveX] Fetching from URL {url}")
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "SinaDLoader Downloader ActiveX",
                                      "Fetching from URL",
                                      data = {
                                                "url": url
                                             },
                                      forward = False)

    try:
        self._window._navigator.fetch(url, redirect_type = "SinaDLoader Exploit")
    except Exception: # pylint:disable=broad-except
        log.ThugLogging.add_behavior_warn('[SinaDLoader Downloader ActiveX] Fetch failed')
