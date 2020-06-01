# AOL ICQ ActiveX Arbitrary File Download and Execut
# CVE-2006-5650

import logging

log = logging.getLogger("Thug")


def DownloadAgent(self, url):
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "AOL ICQ ActiveX",
                                      "Arbitrary File Download and Execute",
                                      cve = "CVE-2006-5650",
                                      data = {
                                                "url": url
                                             }
                                     )

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2006-5650")
    log.ThugLogging.add_behavior_warn('[AOL ICQ ActiveX] Fetching from URL: %s' % (url, ))

    try:
        self._window._navigator.fetch(url, redirect_type = "AOL ICQ Exploit")
    except Exception:
        log.ThugLogging.add_behavior_warn('[AOL ICQ ActiveX] Fetch failed')
