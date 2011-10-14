# Comodo AntiVirus 2.0
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def ExecuteStr(self, cmd, args):
    log.warning('Comodo will execute: ' + cmd + ' ' + args)

