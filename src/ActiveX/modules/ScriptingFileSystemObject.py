
import logging
log = logging.getLogger("Thug.ActiveX")

def OpenTextFile(self, sFilePathAndName, ForWriting = True, flag = True):
    log.warning('[Script.FileSystemObject ActiveX] OpenTextFile("%s", "%s", "%s")' % (sFilePathAndName, ForWriting, flag))

def Write(self, sFileContents):
    log.warning('[Script.FileSystemObject ActiveX] Write("%s")' % (sFileContents, ))

def Close(self):
    log.warning('[Script.FileSystemObject ActiveX] Close()')

def BuildPath(self, arg0, arg1):
    log.warning('[Script.FileSystemObject ActiveX] BuildPath("%s", "%s")' % (arg0, arg1, ))

def GetSpecialFolder(self, arg):
    log.warning('[Script.FileSystemObject ActiveX] GetSpecialFolder(%s)' % (arg, ))
    return '%TEMP%'
