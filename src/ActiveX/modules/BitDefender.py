# BitDefender Online Scanner ActiveX Control
# CVE-2007-5775

def initx(arg):
	if len(arg)>1024:
		add_alert('BitDefender Online Scanner InitX() overflow')

self.initx=initx
