# Microsoft Windows Media Encoder WMEX.DLL ActiveX BufferOverflow vulnerability
# CVE-2008-3008

acct = ActiveXAcct[self]

def GetDetailsString(arg0, arg1):
    global acct

	if len(arg0) > 1023:
		acct.add_alert('WMEX.DLL ActiveX GetDetailsString Method Overflow')

self.GetDetailsString = GetDetailsString
