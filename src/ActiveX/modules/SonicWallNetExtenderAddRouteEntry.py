# SonicWall SSL-VPN NetExtender NELaunchCtrl ActiveX control
# CVE-2007-5603 (AddRouteEntry)

def AddRouteEntry(arg0,arg1):
	if len(arg0)>20:
		add_alert('Overflow in AddRouteEntry arg0')
	if len(arg1)>20:
		add_alert('Overflow in AddRouteEntry arg1')

self.AddRouteEntry=AddRouteEntry
	
