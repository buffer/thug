# Ourgame GLWorld HanGamePluginCn18 Class ActiveX Control
# CVE-2008-0647

import logging
log = logging.getLogger("Thug")

def hgs_startGame(self, arg):
    if len(arg) > 1000:
        log.ThugLogging.add_behavior_warn('[Ourgame GLWorld ActiveX] Overflow in hgs_startGame',
                                   'CVE-2008-0647')

def hgs_startNotify(self, arg):
    if len(arg) > 1000:
        log.ThugLogging.add_behavior_warn('[Ourgame GLWorld ActiveX] Overflow in hgs_startNotify',
                                   'CVE-2008-0647')

