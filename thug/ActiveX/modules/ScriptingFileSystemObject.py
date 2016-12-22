from thug.ActiveX.modules import WScriptShell
import string
import random
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

    arg = int(arg)
    folder = ''
    if arg == 0:
        folder = WScriptShell.ExpandEnvironmentStrings(self, "%windir%")
    elif arg == 1:
        folder = WScriptShell.ExpandEnvironmentStrings(self, "%SystemRoot%\\system32")
    elif arg == 2:
        folder = WScriptShell.ExpandEnvironmentStrings(self, "%TEMP%")

    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] Returning %s for GetSpecialFolder(%s)' % (folder, arg, ))
    return folder


def GetTempName(self):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] GetTempName()')
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
