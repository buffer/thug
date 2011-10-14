# SonicWall SSL-VPN NetExtender NELaunchCtrl ActiveX control
# CVE-2007-5603 (AddRouteEntry)

import logging
log = logging.getLogger("Thug.ActiveX")

def AddRouteEntry(self, arg0, arg1):
    if len(arg0) > 20:
        log.warning('SonicWall SSL-VPN NetExtender NELaunchCtrl ActiveX Overflow in AddRouteEntry arg0')
    if len(arg1) > 20:
        log.warning('SonicWall SSL-VPN NetExtender NELaunchCtrl ActiveX Overflow in AddRouteEntry arg1')

	
