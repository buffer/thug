# OWC10/11.Spreadsheet ActiveX
# CVE-2009-1136

import logging
log = logging.getLogger("Thug")

def _Evaluate(self, *args):
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "OWC 10/11.Spreadsheet ActiveX",
                                      "Attack in _Evaluate function",
                                      cve = "CVE-2009-1136")

def Evaluate(self, *args):
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "OWC 10/11.Spreadsheet ActiveX",
                                      "Attack in Evaluate function",
                                      cve = "CVE-2009-1136")
