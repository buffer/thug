# BaiduBar.dll ActiveX DloadDS() Remote Code Execution Vulnerability
# BUGTRAQ  ID: 25121

import logging
log = logging.getLogger("Thug.ActiveX")

def DloadDS(self, arg0, arg1, arg2):
    if str(arg0).lower().find(".cab") != -1:
        log.warning('BaiduBar.dll ActiveX DloadDS() function is trying to download %s' % (arg0, ))
