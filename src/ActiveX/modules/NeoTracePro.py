# NeoTraceExplorer.NeoTraceLoader ActiveX control (NeoTraceExplorer.dll)
# CVE-2006-06707

import logging
log = logging.getLogger("Thug.ActiveX")

def TraceTarget(self, target):
    if len(target) > 255:
        log.warning('NeoTracePro.TraceTarget overflow in arg0')

