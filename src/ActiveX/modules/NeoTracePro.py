# NeoTraceExplorer.NeoTraceLoader ActiveX control (NeoTraceExplorer.dll)
# CVE-2006-6707

import logging
log = logging.getLogger("Thug")

def TraceTarget(self, target):
    if len(target) > 255:
        log.MAEC.add_behavior_warn('[NeoTraceExplorer.NeoTraceLoader ActiveX] overflow in arg0',
                                   'CVE-2006-6707')

