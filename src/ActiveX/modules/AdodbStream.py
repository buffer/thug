
import logging
log = logging.getLogger("Thug")

def open(self):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] open")

def Write(self, s):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Write")

def SaveToFile(self, filename, opt):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] SaveToFile (%s)" % (filename, ))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Adodb.Stream ActiveX",
                                      "SaveToFile",
                                      data = {
                                                "file": filename
                                             },
                                      forward = False)

def Close(self):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Close")


