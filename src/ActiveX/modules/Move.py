# Move Networks Upgrade Manager 1.x
# CVE-NOMATCH

acct = ActiveXAcct[self]

def Upgrade(arg0, arg1, arg2, arg3):
    global acct

    if len(arg0) > 6000:
        acct.add_alert('Move Networks Upgrade Manager overflow in Upgrade()')

self.Upgrade = Upgrade
