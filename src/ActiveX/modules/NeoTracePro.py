# NeoTraceExplorer.NeoTraceLoader ActiveX control (NeoTraceExplorer.dll)
# CVE-2006-6707

import logging
log = logging.getLogger("Thug")

def TraceTarget(self, target):
    if len(target) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "NeoTraceExplorer.NeoTraceLoader ActiveX",
                                          "Overflow in arg0",
                                          cve = 'CVE-2006-6707')
