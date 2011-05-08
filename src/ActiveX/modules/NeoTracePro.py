# NeoTraceExplorer.NeoTraceLoader ActiveX control (NeoTraceExplorer.dll)
# CVE-2006-06707

def TraceTarget(target):
    if len(target) > 255:
        add_alert('NeoTracePro.TraceTarget overflow in arg0')

self.TraceTarget = TraceTarget
	
