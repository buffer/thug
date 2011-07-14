# GlobalLink ConnectAndEnterRoom ActiveX Control ConnectAndEnterRoom() Method Overflow Vulnerability
# CVE-2007-5722

acct = ActiveXAcct[self]

def ConnectAndEnterRoom(arg0, arg1, arg2, arg3, arg4, arg5):
    global acct

    if len(arg0) > 172:
        acct.add_alert('ConnectAndEnterRoom ActiveX Control ConnectAndEnterRoom() Overflow')

self.ConnectAndEnterRoom = ConnectAndEnterRoom
