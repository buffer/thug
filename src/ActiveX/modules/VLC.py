# VLC ActiveX Control
# CVE-2007-4619, CVE-2007-6262

acct = ActiveXAcct[self]

def getVariable(arg):
    global acct

	if len(arg) > 255:
		acct.add_alert('VLC getVariable() overflow')

def setVariable(arg0, arg1):
    global acct

	if len(arg0) > 255 or len(arg1) > 255:
		acct.add_alert('VLC setVariable() overflow')

def addTarget(arg0, arg1, arg2, arg3):
    global acct

	if len(arg0) > 255 or len(arg1) > 255 or len(arg2) > 255 or len(arg3) > 255:
		acct.add_alert('VLC addTarget() overflow')

self.getVariable = getVariable
self.setVariable = setVariable
self.addTarget   = addTarget
