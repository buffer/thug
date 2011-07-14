# ICQ Toolbar attack
# CVE-NOMATCH

acct = ActiveXAcct[self]

def GetPropertyById(arg0, arg1):
    global acct

    if len(arg1) > 120:
        acct.add_alert('ICQToolbar buffer overflow in GetPropertyById')

self.GetPropertyById = GetPropertyById
