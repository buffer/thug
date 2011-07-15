# RealMedia RealPlayer Ierpplug.DLL ActiveX Control
# CVE-2007-5601

acct = ActiveXAcct[self]

def DoAutoUpdateRequest(arg0, arg1, arg2):
    global acct

    if len(arg0) > 1000 or len(arg1) > 1000:
        acct.add_alert('RealPlayer 10.5 ierpplug.dll overflow in DoAutoUpdateRequest()')

def PlayerProperty(arg):
    global acct

    if arg == 'PRODUCTVERSION':
        return '6.0.14.552'

    if len(arg) > 1000:
        acct.add_alert('RealPlayer 10.5 ierpplug.dll overflow in PlayerProperty()')

def Import(arg):
    global acct

    if len(arg) > 0x8000:
        acct.add_alert('RealPlayer 10.5 ierpplug.dll overflow in Import()')

def SetConsole(val):
    global acct
    
    if len(val) >= 32:
        acct.add_alert('RealPlayer rmoc3260.dll overflow in Console property')

self.DoAutoUpdateRequest = DoAutoUpdateRequest
self.PlayerProperty      = PlayerProperty
self.Import              = Import
Attr2Fun['Console']      = SetConsole
