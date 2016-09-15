
import string
import time
import random
import re
import six
import logging
import hashlib
import pefile
import PyV8
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

    if 'http' not in strCommand:
        return

    self._doRun(strCommand, 1)

def _doRun(self, p, stage):
    if not isinstance(p, six.string_types):
        return

    try:
        pefile.PE(data = p, fast_load = True)
        return
    except: #pylint:disable=bare-except
        pass

    log.ThugLogging.add_code_snippet(p, 'VBScript', 'Contained_Inside')
    log.ThugLogging.add_behavior_warn("[Wscript.Shell ActiveX] Run (Stage %d) Code:\n%s", stage, p)
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
            index = p.index('"http')
        except ValueError:
            break

        p = p[index + 1:]
        s = p.split('"')
        if len(s) < 2:
            break

        url = s[0]
        log.add_behavior_warn("[Wscript.Shell ActiveX] Run (Stage %d) Downloading from URL %s", stage, url)

        try:
            response = self._window._navigator.fetch(url, redirect_type = "doRun")
        except: #pylint:disable=bare-except
            continue

        if response is None:
            continue

        if response.status_code == 404:
            continue

        md5 = hashlib.md5()
        md5.update(response.content)
        log.ThugLogging.add_behavior_warn("[Wscript.Shell ActiveX] Run (Stage %d) Saving file %s", stage, md5.hexdigest())
        p = '"'.join(s[1:])

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
    PyV8.JSEngine.terminateAllThreads()

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
