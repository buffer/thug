# GlobalLink ConnectAndEnterRoom ActiveX Control ConnectAndEnterRoom() Method Overflow Vulnerability
# CVE-2007-5722

import logging
log = logging.getLogger("Thug.ActiveX")

def ConnectAndEnterRoom(self, arg0, arg1, arg2, arg3, arg4, arg5):
    if len(arg0) > 172:
        log.warning('ConnectAndEnterRoom ActiveX Control ConnectAndEnterRoom Overflow')

