# Ourgame GLWorld HanGamePluginCn18 Class ActiveX Control
# CVE-2008-0647

def hgs_startGame(arg):
	if len(arg)>1000:
		add_alert('Overflow in Ourgame GLWorld hgs_startGame()')

def hgs_startNotify(arg):
	if len(arg)>1000:
		add_alert('Overflow in Ourgame GLWorld hgs_startNotify()')

self.hgs_startGame=hgs_startGame
self.hgs_startNotify=hgs_startNotify
