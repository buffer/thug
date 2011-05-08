# iMesh<= 7.1.0.x IMWebControl Class
# CVE-2007-6493, CVE-2007-6492

def ProcessRequestEx(arg):
	if len(arg)==0:
		add_alert('IMWebControl NULL value in ProcessRequestEx()')

def SetHandler(arg):
	if str([arg])=='218959117':
		add_alert('IMWebControl overflow in SetHandler()')

self.ProcessRequestEx=ProcessRequestEx
self.SetHandler=SetHandler
