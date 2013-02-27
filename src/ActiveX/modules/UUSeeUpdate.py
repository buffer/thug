# UUSee UUUpgrade ActiveX Control 'Update' Method Arbitrary File Download Vulnerability
# CVE...

import logging
log = logging.getLogger("Thug")

def Update(self, *args):
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "UUsee UUPgrade ActiveX",
                                      "Attack in Update Method")
