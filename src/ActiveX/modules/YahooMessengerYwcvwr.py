# Yahoo! Messenger 8.x Ywcvwr ActiveX Control
# CVE-2007-4391

acct = ActiveXAcct[self]

def Setserver(name):
    global acct

	if len(name) > 255:
		acct.add_alert('Yahoo! server console overflow')

def GetComponentVersion(arg):
    global acct

	acct.add_alert('Yahoo! GetComponentVersion() overflow')

def initialize():
    return

def send():
    return

def receive():
    return

self.GetComponentVersion = GetComponentVersion
self.initialize          = initialize
self.send                = send
self.receive             = receive
Attr2Fun['server']       = Setserver
