# GlobalLink ConnectAndEnterRoom ActiveX Control ConnectAndEnterRoom() Method Overflow Vulnerability
# CVE-2007-5722

def ConnectAndEnterRoom(arg0,arg1,arg2,arg3,arg4,arg5):
	if len(arg0)>172:
		add_alert('ConnectAndEnterRoom ActiveX Control ConnectAndEnterRoom() Overflow')

self.ConnectAndEnterRoom=ConnectAndEnterRoom
