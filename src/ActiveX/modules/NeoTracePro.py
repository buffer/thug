# NeoTraceExplorer.NeoTraceLoader ActiveX control (NeoTraceExplorer.dll)
# CVE-2006-06707

acct = ActiveXAcct[self]

def TraceTarget(target):
    global acct

    if len(target) > 255:
        acct.add_alert('NeoTracePro.TraceTarget overflow in arg0')

self.TraceTarget = TraceTarget
	
