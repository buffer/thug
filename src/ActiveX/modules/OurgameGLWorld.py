# Ourgame GLWorld HanGamePluginCn18 Class ActiveX Control
# CVE-2008-0647

acct = ActiveXAcct[self]

def hgs_startGame(arg):
    global acct

    if len(arg) > 1000:
        acct.add_alert('Overflow in Ourgame GLWorld hgs_startGame()')

def hgs_startNotify(arg):
    global acct

    if len(arg) > 1000:
        acct.add_alert('Overflow in Ourgame GLWorld hgs_startNotify()')

self.hgs_startGame   = hgs_startGame
self.hgs_startNotify = hgs_startNotify
