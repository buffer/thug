# Chinagames iGame CGAgent ActiveX Control Buffer Overflow
# CVE-2009-1800

acct = ActiveXAcct[self]

def CreateChinagames(arg0):
    global acct

    if len(arg0) > 428:
        acct.add_alert('CGAgent ActiveX CreateChinagames Method Buffer Overflow')

self.CreateChinagames = CreateChinagames
