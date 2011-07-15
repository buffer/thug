# SonicWall SSL-VPN NetExtender NELaunchCtrl ActiveX control
# CVE-2007-5603 (AddRouteEntry)

acct = ActiveXAcct[self]

def AddRouteEntry(arg0, arg1):
    global acct

    if len(arg0) > 20:
        acct.add_alert('Overflow in AddRouteEntry arg0')
    if len(arg1) > 20:
        acct.add_alert('Overflow in AddRouteEntry arg1')

self.AddRouteEntry = AddRouteEntry
	
