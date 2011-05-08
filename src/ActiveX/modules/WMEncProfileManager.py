# Microsoft Windows Media Encoder WMEX.DLL ActiveX BufferOverflow vulnerability
# CVE-2008-3008

def GetDetailsString(arg0,arg1):
	if(len(arg0)>1023):
		add_alert('WMEX.DLL ActiveX GetDetailsString Method Overflow')

self.GetDetailsString=GetDetailsString
