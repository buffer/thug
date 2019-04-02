
import string
import time
import random
import re
import logging
import hashlib
import six
import pefile

from thug.Magic.Magic import Magic
from thug.OS.Windows import win32_registry
from thug.OS.Windows import win32_registry_map

log = logging.getLogger("Thug")


class _Environment(object):
    def __init__(self, strType):
        self.strType = strType

    def Item(self, item):
        log.ThugLogging.add_behavior_warn("[WScript.Shell ActiveX] Getting Environment Item: %s" % (item, ))
        return item


def Run(self, strCommand, intWindowStyle = 1, bWaitOnReturn = False):
    log.ThugLogging.add_behavior_warn("[WScript.Shell ActiveX] Executing: %s" % (strCommand, ))
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
    if not isinstance(p, six.string_types):
        return

    try:
        pefile.PE(data = p, fast_load = True)
        return
    except Exception:
        pass

    if log.ThugOpts.code_logging:
        log.ThugLogging.add_code_snippet(p, 'VBScript', 'Contained_Inside')

    log.ThugLogging.add_behavior_warn("[Wscript.Shell ActiveX] Run (Stage %d) Code:\n%s" % (stage, p))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "WScript.Shell ActiveX",
                                      "Run",
                                      data = {
                                                "stage" : stage,
                                                "code"  : p,
                                             },
                                      forward = False)

    while True:
        try:
            index = p.index('http')
        except ValueError:
            break

        p = p[index:]

        s = p.split()
        if len(s) < 2:
            break

        url = s[0]
        if url.endswith(("'", '"')):
            url = url[:-1]

        log.ThugLogging.add_behavior_warn("[Wscript.Shell ActiveX] Run (Stage %d) Downloading from URL %s" % (stage, url))

        try:
            response = self._window._navigator.fetch(url, redirect_type = "doRun")
        except Exception:
            continue

        if response is None:
            continue

        if response.status_code == 404:
            continue

        md5 = hashlib.md5()
        md5.update(response.content)
        md5sum = md5.hexdigest()
        sha256 = hashlib.sha256()
        sha256.update(response.content)
        sha256sum = sha256.hexdigest()

        log.ThugLogging.add_behavior_warn("[Wscript.Shell ActiveX] Run (Stage %d) Saving file %s" % (stage, md5sum, ))
        p = " ".join(s[1:])

        data = {
                'status'  : response.status_code,
                'content' : response.content,
                'md5'	  : md5sum,
                'sha256'  : sha256sum,
                'fsize'   : len(response.content),
                'ctype'   : response.headers.get('content-type', 'unknown'),
                'mtype'   : Magic(response.content).get_mime(),
        }

        log.ThugLogging.log_location(url, data)
        log.TextClassifier.classify(url, response.content)

        self._doRun(response.content, stage + 1)


def Environment(self, strType = None):
    log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] Environment("%s")' % (strType, ))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "WScript.Shell ActiveX",
                                      "Environment",
                                      data = {
                                                "env" : strType
                                             },
                                      forward = False)
    return _Environment(strType)


def ExpandEnvironmentStrings(self, strWshShell):
    log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] Expanding environment string "%s"' % (strWshShell, ))
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

    log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] Expanded environment string to "%s"' % (strWshShell, ))
    return strWshShell


def CreateObject(self, strProgID, strPrefix = ""):
    import thug.ActiveX as ActiveX

    log.ThugLogging.add_behavior_warn("[WScript.Shell ActiveX] CreateObject (%s)" % (strProgID))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "WScript.Shell ActiveX",
                                      "CreateObject",
                                      data = {
                                          "strProgID": strProgID,
                                          "strPrefix": strPrefix
                                      },
                                      forward = False)

    return ActiveX.ActiveX._ActiveXObject(self._window, strProgID)


def Sleep(self, intTime):
    log.ThugLogging.add_behavior_warn("[WScript.Shell ActiveX] Sleep(%s)" % (intTime))
    time.sleep(intTime * 0.001)


def Quit(self, code):
    log.ThugLogging.add_behavior_warn("[WScript.Shell ActiveX] Quit(%s)" % code)
    # log.JSEngine.terminateAllThreads()


def Echo(self, text):
    log.ThugLogging.add_behavior_warn("[WScript.Shell ActiveX] Echo(%s)" % (text))


def valueOf(self):
    return "Windows Script Host"


def toString(self):
    return "Windows Script Host"


def SpecialFolders(self, strFolderName):
    log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] Received call to SpecialFolders property "%s"' % (strFolderName, ))
    folderPath = log.ThugOpts.Personality.getSpecialFolder(strFolderName)
    if folderPath:
        folderPath = ExpandEnvironmentStrings(self, folderPath)
    return "{}".format(folderPath)


def CreateShortcut(self, strPathname):
    log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] CreateShortcut "%s"' % (strPathname, ))
    obj = CreateObject(self, "wscript.shortcut")
    obj.FullName = strPathname
    return obj


def RegRead(self, registry):
    if registry.lower() in win32_registry:
        value = win32_registry[registry.lower()]
        log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] RegRead("{}") = "{}"'.format(registry, value))
        return value

    if registry.lower() in win32_registry_map:
        value = log.ThugOpts.Personality.getShellVariable(win32_registry_map[registry.lower()])
        log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] RegRead("{}") = "{}"'.format(registry, value))
        return value

    log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] RegRead("{}") = {}'.format(registry, 'NOT FOUND'))
    return ''


def RegWrite(self, registry, value, strType = "REG_SZ"):
    log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] RegWrite("{}", "{}", "{}")'.format(registry, value, strType))
    win32_registry[registry.lower()] = value


def Popup(self, title = "", timeout = 0, message = "", _type = 0):
    log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] Popup("{}", "{}", "{}")'.format(title, message, _type))
    return 0
