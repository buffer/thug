# Move Networks Upgrade Manager 1.x
# CVE-NOMATCH

def Upgrade(arg0,arg1,arg2,arg3):
	if len(arg0)>6000:
		add_alert('Move Networks Upgrade Manager overflow in Upgrade()')

self.Upgrade=Upgrade
