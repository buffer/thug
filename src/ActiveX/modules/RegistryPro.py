# Registry Pro (epRegPro.ocx)
# CVE-NOMATCH

def DeleteKey(arg0, arg1):
	if arg0==80000002:
		add_alert('RegistryPro deleting HKEY_LOCAL_MACHINE key ' + arg1)
	if arg0==80000001:
		add_alert('RegistryPro deleting HKEY_CURRENT_USER key ' + arg1)
	
def About():
	add_alert('RegistryPro called About()')

self.DeleteKey=DeleteKey
self.About=About
