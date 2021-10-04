# Symantec AppStream LaunchObj ActiveX Arbitrary File Download and Execute
# CVE-2008-4388

import logging

log = logging.getLogger("Thug")


def installAppMgr(self, url):
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Symantec AppStream LaunchObj ActiveX",
                                      "Arbitrary File Download and Execute",
                                      cve = "CVE-2008-4388",
                                      data = {
                                                "url": url
                                             }
                                     )

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2008-4388")
    log.ThugLogging.add_behavior_warn(f"[Symantec AppStream LaunchObj ActiveX] Fetching from URL {url}")

    try:
        self._window._navigator.fetch(url, redirect_type = "CVE-2008-4388")
    except Exception: # pylint:disable=broad-except
        log.ThugLogging.add_behavior_warn('[Symantec AppStream LaunchObj ActiveX] Fetch failed')
