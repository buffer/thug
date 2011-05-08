# Chinagames iGame CGAgent ActiveX Control Buffer Overflow
# CVE-2009-1800

def CreateChinagames(arg0):
	if len(arg0)>428:
		add_alert('CGAgent ActiveX CreateChinagames Method BUffer Overflow')

self.CreateChinagames=CreateChinagames
