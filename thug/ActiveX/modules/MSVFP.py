# Microsoft VFP_OLE_Server

import logging

log = logging.getLogger("Thug")


def foxcommand(self, cmd):
    log.ThugLogging.add_behavior_warn(f'[Microsoft VFP_OLE_Server ActiveX] Trying to run: {cmd}')
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Microsoft VFP_OLE_Server ActiveX",
                                      "Trying to run",
                                      data = {
                                                "command": cmd
                                             },
                                      forward = False)
