# Yahoo! Messenger 8.x YVerInfo.dll ActiveX Control
# CVE-2007-4515

import logging
log = logging.getLogger("Thug.ActiveX")

def fvcom(self, arg0):
    if len(arg0) > 20:
        log.warning('YahooYVerInfo ActiveX Overflow in fvCom arg0')

def info(self, arg0):
    if len(arg0) > 20:
        log.warning('YahooYVerInfo ActiveX Overflow in info arg0')

