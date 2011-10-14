
import logging
log = logging.getLogger("Thug.ActiveX")

def ShellExecute(self, *args):
    cmdLine = ''
    for arg in args:
        if len(arg) == 0:
            break
        cmdLine += str(arg)
    
    log.warning('[Shell.Application ActiveX] ShellExecute command: ' + cmdLine)

