# Toshiba Surveillance (Surveillix) RecordSend Class (MeIpCamX.DLL 1.0.0.4)
# CVE-NOMATCH

def SetPort(arg):
	if len(arg)>10:
		add_alert('Toshiba Surveillance overflow in SetPort()')

def SetIpAddress(arg):
	if len(arg)>18:
		add_alert('Toshiba Surveillance overflow in SetIpAddress()')

self.SetPort=SetPort
self.SetIpAddress=SetIpAddress
