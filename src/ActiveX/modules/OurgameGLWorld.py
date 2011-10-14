# Ourgame GLWorld HanGamePluginCn18 Class ActiveX Control
# CVE-2008-0647

import logging
log = logging.getLogger("Thug.ActiveX")

def hgs_startGame(self, arg):
    if len(arg) > 1000:
        log.warning('Ourgame GLWorld ActiveX Overflow in hgs_startGame')

def hgs_startNotify(self, arg):
    if len(arg) > 1000:
        log.warning('Ourgame GLWorld ActiveX Overflow in hgs_startNotify')

