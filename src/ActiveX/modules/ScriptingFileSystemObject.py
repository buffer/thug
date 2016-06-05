
import logging
log = logging.getLogger("Thug")

def OpenTextFile(self, sFilePathAndName, ForWriting = True, flag = True):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] OpenTextFile("%s", "%s", "%s")' % (sFilePathAndName, ForWriting, flag))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Script.FileSystemObject ActiveX",
                                      "OpenTextFile",
                                      data = {
                                                "filename"  : sFilePathAndName,
                                                "ForWriting": ForWriting,
                                                "flag"      : flag
                                             },
                                      forward = False)

def Write(self, sFileContents):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] Write("%s")' % (sFileContents, ))

def Close(self):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] Close()')

def BuildPath(self, arg0, arg1):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] BuildPath("%s", "%s")' % (arg0, arg1, ))
    return "%s\%s" % (arg0, arg1)

def GetSpecialFolder(self, arg):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] GetSpecialFolder(%s)' % (arg, ))
    return '%TEMP%'
