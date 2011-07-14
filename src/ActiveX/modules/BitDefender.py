# BitDefender Online Scanner ActiveX Control
# CVE-2007-5775

acct = ActiveXAcct[self]

def initx(arg):
    global acct

    if len(arg) > 1024:
        acct.add_alert('BitDefender Online Scanner InitX() overflow')

self.initx = initx
