# Comodo AntiVirus 2.0
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def ExecuteStr(self, cmd, args):
    log.ThugLogging.add_behavior_warn('[Comodo AntiVirus ActiveX] Trying to execute: ' + cmd + ' ' + args)

