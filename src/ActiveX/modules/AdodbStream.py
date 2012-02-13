
import logging
log = logging.getLogger("Thug")

def open(self):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] open")

def Write(self, s):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Write")

def SaveToFile(self, filename, opt):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] SaveToFile (%s)" % (filename, ))

def Close(self):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Close")


