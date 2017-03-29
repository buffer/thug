
import logging
log = logging.getLogger("Thug")


def LinkSBIcons(self):
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "AOL ActiveX",
                                      "Attack in LinkSBIcons function",
                                      cve = "CVE-2006-5820")

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2006-5820", None)
