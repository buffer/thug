
import os
import string
import random
import logging

from thug.ActiveX.modules import WScriptShell
from thug.ActiveX.modules import TextStream
from thug.ActiveX.modules import File
from thug.ActiveX.modules import Folder
from thug.OS.Windows import win32_files
from thug.OS.Windows import win32_folders

log = logging.getLogger("Thug")


def BuildPath(self, arg0, arg1): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] BuildPath("{arg0}", "{arg1}")')
    return f"{arg0}\\{arg1}"


def CopyFile(self, source, destination, overwritefiles = False): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] CopyFile("{source}", "{destination}")')
    log.TextFiles[destination] = log.TextFiles[source]


def DeleteFile(self, filespec, force = False): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] DeleteFile("{filespec}", {force})')


def CreateTextFile(self, filename, overwrite = False, _unicode = False): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] CreateTextFile("{filename}", '
                                      f'"{overwrite}", '
                                      f'"{_unicode}")')
    stream = TextStream.TextStream()
    stream._filename = filename
    return stream


def CreateFolder(self, path): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] CreateFolder("{path}")')
    return Folder.Folder(path)


def FileExists(self, filespec): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] FileExists("{filespec}")')
    if not filespec:
        return True

    if filespec.lower() in win32_files:
        return True

    if getattr(log, "TextFiles", None) and filespec in log.TextFiles:
        return True

    return False


def FolderExists(self, folder): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] FolderExists("{folder}")')
    return str(folder).lower() in win32_folders


def GetExtensionName(self, path): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] GetExtensionName("{path}")')
    ext = os.path.splitext(path)[1]
    return ext if ext else ""


def GetFile(self, filespec): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] GetFile("{filespec}")')
    return File.File(filespec)


def GetSpecialFolder(self, arg):
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] GetSpecialFolder("{arg}")')

    arg = int(arg)
    folder = ''
    if arg == 0:
        folder = WScriptShell.ExpandEnvironmentStrings(self, "%windir%")
    elif arg == 1:
        folder = WScriptShell.ExpandEnvironmentStrings(self, "%SystemRoot%\\system32")
    elif arg == 2:
        folder = WScriptShell.ExpandEnvironmentStrings(self, "%TEMP%")

    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] Returning {folder} for GetSpecialFolder("{arg}")')
    return folder


def GetTempName(self): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn('[Scripting.FileSystemObject ActiveX] GetTempName()')
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))


def MoveFile(self, source, destination): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] MoveFile("{source}", "{destination}")')
    log.TextFiles[destination] = log.TextFiles[source]
    del log.TextFiles[source]


def OpenTextFile(self, sFilePathAndName, ForWriting = True, flag = True):
    log.ThugLogging.add_behavior_warn(f'[Scripting.FileSystemObject ActiveX] OpenTextFile("{sFilePathAndName}", '
                                      f'"{ForWriting}" ,'
                                      f'"{flag}")')

    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Scripting.FileSystemObject ActiveX",
                                      "OpenTextFile",
                                      data = {
                                                "filename"  : sFilePathAndName,
                                                "ForWriting": ForWriting,
                                                "flag"      : flag
                                             },
                                      forward = False)

    if getattr(log, 'TextFiles', None) is None:
        log.TextFiles = {}

    if sFilePathAndName in log.TextFiles:
        return log.TextFiles[sFilePathAndName]

    stream = TextStream.TextStream()
    stream._filename = sFilePathAndName

    if log.ThugOpts.local and sFilePathAndName in (log.ThugLogging.url, ): # pragma: no cover
        with open(sFilePathAndName, encoding = 'utf-8', mode = 'r') as fd:
            data = fd.read()

        stream.Write(data)

    log.TextFiles[sFilePathAndName] = stream
    return stream
