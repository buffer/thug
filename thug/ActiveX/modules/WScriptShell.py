
import string
import time
import random
import re
import logging
import hashlib
import pefile

from thug.ActiveX.modules.WScriptExec import WScriptExec
from thug.OS.Windows import win32_registry
from thug.OS.Windows import win32_registry_map

log = logging.getLogger("Thug")


class _Environment:
    def __init__(self, strType):
        self.strType = strType

    def Item(self, item): # pragma: no cover,pylint:disable=no-self-use
        log.ThugLogging.add_behavior_warn(f"[WScript.Shell ActiveX] Getting Environment Item: {item}")
        return item


def Run(self, strCommand, intWindowStyle = 1, bWaitOnReturn = False): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f"[WScript.Shell ActiveX] Executing: {strCommand}")
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "WScript.Shell ActiveX",
                                      "Run",
                                      data = {
                                                "command" : strCommand
                                             },
                                      forward = False)

    data = {
        'content' : strCommand,
    }

    log.ThugLogging.log_location(log.ThugLogging.url, data)
    log.TextClassifier.classify(log.ThugLogging.url, strCommand)

    if 'http' not in strCommand:
        return

    self._doRun(strCommand, 1)


def _doRun(self, p, stage):
    try:
        pefile.PE(data = p, fast_load = True)
        return
    except Exception: # pylint:disable=broad-except
        pass

    if not isinstance(p, str):
        return # pragma: no cover

    if log.ThugOpts.code_logging:
        log.ThugLogging.add_code_snippet(p, 'VBScript', 'Contained_Inside')

    log.ThugLogging.add_behavior_warn(f"[WScript.Shell ActiveX] Run (Stage {stage}) Code:\n{p}")
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "WScript.Shell ActiveX",
                                      "Run",
                                      data = {
                                                "stage" : stage,
                                                "code"  : p,
                                             },
                                      forward = False)

    s = None

    while True:
        if s is not None and len(s) < 2:
            break

        try:
            index = p.index('http')
        except ValueError:
            break

        p   = p[index:]
        s   = p.split()
        p   = p[1:]
        url = s[0]
        url = url[:-1] if url.endswith(("'", '"')) else url
        url = url.split('"')[0]
        url = url.split("'")[0]

        log.ThugLogging.add_behavior_warn(f"[WScript.Shell ActiveX] Run (Stage {stage}) Downloading from URL {url}")

        try:
            response = self._window._navigator.fetch(url, redirect_type = "doRun")
        except Exception: # pragma: no cover,pylint:disable=broad-except
            continue

        if response is None or not response.ok:
            continue # pragma: no cover

        md5 = hashlib.md5() # nosec
        md5.update(response.content)
        md5sum = md5.hexdigest()
        sha256 = hashlib.sha256()
        sha256.update(response.content)
        sha256sum = sha256.hexdigest()

        log.ThugLogging.add_behavior_warn(f"[WScript.Shell ActiveX] Run (Stage {stage}) Saving file {md5sum}")
        p = " ".join(s[1:])

        data = {
                'status'  : response.status_code,
                'content' : response.content,
                'md5'	  : md5sum,
                'sha256'  : sha256sum,
                'fsize'   : len(response.content),
                'ctype'   : response.headers.get('content-type', 'unknown'),
                'mtype'   : log.Magic.get_mime(response.content),
        }

        log.ThugLogging.log_location(url, data)
        log.TextClassifier.classify(url, response.content)

        self._doRun(response.content, stage + 1)


def Environment(self, strType = None):
    log.ThugLogging.add_behavior_warn(f'[WScript.Shell ActiveX] Environment("{strType}")')
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "WScript.Shell ActiveX",
                                      "Environment",
                                      data = {
                                                "env" : strType
                                             },
                                      forward = False)
    return _Environment(strType)


def ExpandEnvironmentStrings(self, strWshShell):
    log.ThugLogging.add_behavior_warn(f'[WScript.Shell ActiveX] Expanding environment string "{strWshShell}"')
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "WScript.Shell ActiveX",
                                      "ExpandEnvironmentStrings",
                                      data = {
                                                "wshshell" : strWshShell
                                             },
                                      forward = False)

    # Substitute shell variables
    strWshShell = re.sub(
        r'%([a-zA-Z-0-9_\(\)]+)%',
        (lambda m: log.ThugOpts.Personality.getShellVariable(m.group(1))),
        strWshShell)

    # Generate random username
    strWshShell = strWshShell.replace(
        '{{username}}',
        ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8)))

    # Generate random computer name
    strWshShell = strWshShell.replace(
        '{{computername}}',
        ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8)))

    log.ThugLogging.add_behavior_warn(f'[WScript.Shell ActiveX] Expanded environment string to "{strWshShell}"')
    return strWshShell


def CreateObject(self, strProgID, strPrefix = ""):
    from thug import ActiveX

    log.ThugLogging.add_behavior_warn(f"[WScript.Shell ActiveX] CreateObject ({strProgID})")
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "WScript.Shell ActiveX",
                                      "CreateObject",
                                      data = {
                                          "strProgID": strProgID,
                                          "strPrefix": strPrefix
                                      },
                                      forward = False)

    return ActiveX.ActiveX._ActiveXObject(self._window, strProgID)


def Sleep(self, intTime): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f"[WScript.Shell ActiveX] Sleep({intTime})")
    time.sleep(intTime * 0.001)


def Quit(self, code): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f"[WScript.Shell ActiveX] Quit({code})")


def Exec(self, path): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f"[WScript.Shell ActiveX] Exec({path})")
    return WScriptExec()


def Echo(self, text): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f"[WScript.Shell ActiveX] Echo({text})")


def valueOf(self): # pylint:disable=unused-argument
    return "Windows Script Host"


def toString(self): # pylint:disable=unused-argument
    return "Windows Script Host"


def SpecialFolders(self, strFolderName):
    log.ThugLogging.add_behavior_warn(f'[WScript.Shell ActiveX] Received call to SpecialFolders property "{strFolderName}"')
    folderPath = log.ThugOpts.Personality.getSpecialFolder(strFolderName)
    if folderPath:
        folderPath = ExpandEnvironmentStrings(self, folderPath)

    return f"{folderPath}"


def CreateShortcut(self, strPathname):
    log.ThugLogging.add_behavior_warn(f'[WScript.Shell ActiveX] CreateShortcut "{strPathname}"')
    obj = CreateObject(self, "wscript.shortcut")
    obj.FullName = strPathname
    return obj


def RegRead(self, registry): # pylint:disable=unused-argument
    if registry.lower() in win32_registry:
        value = win32_registry[registry.lower()]
        log.ThugLogging.add_behavior_warn(f'[WScript.Shell ActiveX] RegRead("{registry}") = "{value}"')
        return value

    if registry.lower() in win32_registry_map:
        value = log.ThugOpts.Personality.getShellVariable(win32_registry_map[registry.lower()])
        log.ThugLogging.add_behavior_warn(f'[WScript.Shell ActiveX] RegRead("{registry}") = "{value}"')
        return value

    log.ThugLogging.add_behavior_warn(f'[WScript.Shell ActiveX] RegRead("{registry}") = NOT FOUND')
    return ''


def RegWrite(self, registry, value, strType = "REG_SZ"): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[WScript.Shell ActiveX] RegWrite("{registry}", "{value}", "{strType}")')
    win32_registry[registry.lower()] = value


def Popup(self, title = "", timeout = 0, message = "", _type = 0): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[WScript.Shell ActiveX] Popup("{title}", "{message}", "{_type}")')
    return 0
