# RealMedia RealPlayer Ierpplug.DLL ActiveX Control
# CVE-2007-5601

def DoAutoUpdateRequest(arg0, arg1, arg2):
	if len(arg0) > 1000 or len(arg1) > 1000:
		add_alert('RealPlayer 10.5 ierpplug.dll overflow in DoAutoUpdateRequest()')

def PlayerProperty(arg):
	if len(arg) > 1000:
		add_alert('RealPlayer 10.5 ierpplug.dll overflow in PlayerProperty()')
	elif arg=='PRODUCTVERSION':
		return '6.0.14.552'

def Import(arg):
	if len(arg) > 0x8000:
		add_alert('RealPlayer 10.5 ierpplug.dll overflow in Import()')

def SetConsole(val):
	if len(val) >= 32:
	    add_alert('RealPlayer rmoc3260.dll overflow in Console property')

self.DoAutoUpdateRequest = DoAutoUpdateRequest
self.PlayerProperty      = PlayerProperty
self.Import              = Import
Attr2Fun['Console']      = SetConsole
