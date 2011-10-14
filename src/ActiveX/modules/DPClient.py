# Xunlei DPClient.Vod.1 ActiveX Control DownURL2 Method Remote Buffer Overflow Vulnerability
# CVE-2007-5064

import logging
log = logging.getLogger("ActiveX.Thug")

def DownURL2(self, arg0, *args):
    if len(arg0) > 1024:
        log.warning('DPClient.Vod.1 ActiveX Control DownURL2 Method Buffer Overflow')


