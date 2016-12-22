# Rising Online Virus Scanner Web Scan ActiveX Control
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def UpdateEngine(self):
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Rising Online Virus Scanner Web Scan ActiveX",
                                      "UpdateEngine Method vulnerability")
