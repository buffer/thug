
import logging
log = logging.getLogger("Thug")

def GetVariable(self, arg):
    if arg == "$version":
        return "WIN 10,0,64,0"
