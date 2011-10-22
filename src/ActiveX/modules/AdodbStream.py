
import logging
log = logging.getLogger("Thug.ActiveX")

def open(self):
    log.warning("[Adodb.Stream ActiveX] open")

def Write(self, s):
    log.warning("[Adodb.Stream ActiveX] Write")

def SaveToFile(self, filename, opt):
    log.warning("[Adodb.Stream ActiveX] SaveToFile (%s)" % (filename, ))

def Close(self):
    log.warning("[Adodb.Stream ActiveX] Close")


