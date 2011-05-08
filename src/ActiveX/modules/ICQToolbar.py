# ICQ Toolbar attack
# CVE-NOMATCH

def GetPropertyById(arg0,arg1):
	if len(arg1)>120:
		add_alert('ICQToolbar buffer overflow in GetPropertyById')

self.GetPropertyById=GetPropertyById
