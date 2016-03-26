
import string
import random
import re
import logging
log = logging.getLogger("Thug")


class _Environment:
    def __init__(self, strType):
        self.strType = strType

    def Item(self, item):
        log.ThugLogging.add_behavior_warn("[WScript.Shell ActiveX] Getting Environment Item: %s" % (item, ))
        return item


def Run(self, strCommand, intWindowStyle = 1, bWaitOnReturn = False):
    log.ThugLogging.add_behavior_warn("[WScript.Shell ActiveX] Executing: %s" % (strCommand, ))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "WScript.Shell ActiveX",
                                      "Execute",
                                      data = {
                                                "command" : strCommand
                                             },
                                      forward = False)

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
    log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] Expanding: ("%s")' % (strWshShell, ))
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

    return strWshShell


def CreateObject(self, strProgID, strPrefix = ""):
    import ActiveX

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
    import time

    time.sleep(intTime * 0.01)

    log.ThugLogging.add_behavior_warn("[WScript.Shell ActiveX] Sleep (%s)" % (intTime))
