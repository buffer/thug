# Yahoo! Messenger 8.x YVerInfo.dll ActiveX Control
# CVE-2007-4515

acct = ActiveXAcct[self]

def fvcom(arg0):
    global acct

	if len(arg0) > 20:
		acct.add_alert('Overflow in YahooYVerInfo.fvCom() arg0')

def info(arg0):
    global acct

	if len(arg0) > 20:
		acct.add_alert('Overflow in YahooYVerInfo.info() arg0')

self.fvcom = fvcom
self.info  = info
