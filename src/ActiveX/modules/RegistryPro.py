# Registry Pro (epRegPro.ocx)
# CVE-NOMATCH

acct = ActiveXAcct[self]

def DeleteKey(arg0, arg1):
    global acct

    if arg0 in (80000001, 80000002, ):
        acct.add_alert('RegistryPro deleting HKEY_LOCAL_MACHINE key ' + arg1)
	
def About():
    global acct

    acct.add_alert('RegistryPro called About()')


self.DeleteKey = DeleteKey
self.About     = About
