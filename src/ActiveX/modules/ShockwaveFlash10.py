
import logging
log = logging.getLogger("Thug.ActiveX")

def GetVariable(self, arg):
    if arg == "$version":
        return "WIN 10,0,64,0"
