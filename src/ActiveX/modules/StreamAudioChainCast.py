# StreamAudio ChainCast VMR Client Proxy ActiveX Control 3.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def InternalTuneIn(self, arg0, arg1, arg2, arg3, arg4):
    if len(arg0) > 248:
        log.ThugLogging.add_behavior_warn('[StreamAudio ChainCast VMR Client Proxy ActiveX] Buffer overflow in arg0')
