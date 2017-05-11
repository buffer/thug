from thug.ActiveX.modules import WScriptShell
from thug.ActiveX.modules import TextStream
from thug.ActiveX.modules import File
from thug.OS.Windows import win32_files
from thug.OS.Windows import win32_folders

import os
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


    stream = TextStream.TextStream()
    stream._filename = sFilePathAndName
    return stream

def Write(self, sFileContents):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] Write("%s")' % (sFileContents, ))


def Close(self):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] Close()')


def BuildPath(self, arg0, arg1):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] BuildPath("%s", "%s")' % (arg0, arg1, ))
    return "%s\%s" % (arg0, arg1)


def GetSpecialFolder(self, arg):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] GetSpecialFolder("%s")' % (arg, ))

    arg = int(arg)
    folder = ''
    if arg == 0:
        folder = WScriptShell.ExpandEnvironmentStrings(self, "%windir%")
    elif arg == 1:
        folder = WScriptShell.ExpandEnvironmentStrings(self, "%SystemRoot%\\system32")
    elif arg == 2:
        folder = WScriptShell.ExpandEnvironmentStrings(self, "%TEMP%")

    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] Returning %s for GetSpecialFolder("%s")' % (folder, arg, ))
    return folder


def GetTempName(self):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] GetTempName()')
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))


def FileExists(self, filespec):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] FileExists("%s")' % (filespec, ))
    if filespec.lower() in win32_files:
        return True

    return False


def CreateTextFile(self, filename, overwrite = False, _unicode = False):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] CreateTextFile("%s", "%s", "%s")' % (filename, overwrite, _unicode))
    stream = TextStream.TextStream()
    stream._filename = filename
    return stream


def GetFile(self, filespec):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] GetFile("%s")' % (filespec, ))
    return File.File(filespec)


def GetExtensionName(self, path):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] GetExtensionName("%s")' % (path, ))
    name, ext = os.path.splitext(path)
    return ext if ext else ""


def MoveFile(self, source, destination):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] MoveFile("%s", "%s")' % (source, destination))


def FolderExists(self, folder):
    log.ThugLogging.add_behavior_warn('[Script.FileSystemObject ActiveX] FolderExists("%s")' % (folder, ))
    return str(folder).lower() in win32_folders
