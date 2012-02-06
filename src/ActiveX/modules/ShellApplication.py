
import logging
log = logging.getLogger("Thug")

def ShellExecute(self, *args):
    cmdLine = ''
    for arg in args:
        if len(arg) == 0:
            break
        cmdLine += str(arg)

    log.MAEC.add_behavior_warn('[Shell.Application ActiveX] ShellExecute command: ' + cmdLine)

