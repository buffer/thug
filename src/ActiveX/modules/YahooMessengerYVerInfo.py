# Yahoo! Messenger 8.x YVerInfo.dll ActiveX Control
# CVE-2007-4515

def fvcom(arg0):
	if len(arg0)>20:
		add_alert('Overflow in YahooYVerInfo.fvCom() arg0')

def info(arg0):
	if len(arg0)>20:
		add_alert('Overflow in YahooYVerInfo.info() arg0')

self.fvcom=fvcom
self.info=info
