# Comodo AntiVirus 2.0
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def ExecuteStr(self, cmd, args):
    log.MAEC.add_behavior_warn('Comodo will execute: ' + cmd + ' ' + args)

