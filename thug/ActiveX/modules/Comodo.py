# Comodo AntiVirus 2.0
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def ExecuteStr(self, cmd, args):
    log.ThugLogging.add_behavior_warn('[Comodo AntiVirus ActiveX] Trying to execute: ' + cmd + ' ' + args)
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Comodo AntiVirus ActiveX",
                                      "Trying to execute",
                                      forward = False,
                                      data = {
                                                "command": cmd,
                                                "args"   : args
                                             }
                                      )
