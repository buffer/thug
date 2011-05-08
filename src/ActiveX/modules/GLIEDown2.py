# Ourgame GLWorld GLIEDown2.dll ActiveX Control Vulnerabilities

def IEStartNative(arg0,arg1,arg2):
	if len(arg0)>220:
		add_alert('GLWorld GLIEDown2.dll ActiveX IEStartNative Method Buffer Overflow')

self.IEStartNative=IEStartNative
