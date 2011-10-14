# StreamAudio ChainCast VMR Client Proxy ActiveX Control 3.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def InternalTuneIn(self, arg0, arg1, arg2, arg3, arg4):
    if len(arg0) > 248:
        log.warning('StreamAudio ChainCast ProxyManager buffer overflow in arg0')
