
import logging
log = logging.getLogger("Thug")

def ShellExecute(self, *args):
    cmdLine = ''
    for arg in args:
        if not arg or len(arg) == 0:
            continue

        cmdLine += str(arg)

    log.ThugLogging.add_behavior_warn('[Shell.Application ActiveX] ShellExecute command: ' + cmdLine)
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Shell.Application ActiveX",
                                      "ShellExecute command",
                                      data = {
                                                "command" : cmdLine
                                             },
                                      forward = False)
