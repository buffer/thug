# Microsoft Windows Media Encoder WMEX.DLL ActiveX BufferOverflow vulnerability
# CVE-2008-3008

import logging
log = logging.getLogger("Thug.ActiveX")

def GetDetailsString(self, arg0, arg1):
    if len(arg0) > 1023:
        log.warning('WMEX.DLL ActiveX GetDetailsString Method Overflow')
