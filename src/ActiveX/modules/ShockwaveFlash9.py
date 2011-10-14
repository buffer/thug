
import logging
log = logging.getLogger("Thug.ActiveX")

def GetVariable(self, arg):
    if arg == "$version":
        return "WIN 9,0,64,0"

