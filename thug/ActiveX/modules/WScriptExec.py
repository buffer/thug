import logging
import random

from thug.ActiveX.modules.TextStream import TextStream

log = logging.getLogger("Thug")


class WScriptExec:
    def __init__(self):
        self._StdIn  = TextStream()
        self._StdOut = TextStream()
        self._StdErr = TextStream()

    @property
    def ExitCode(self):
        log.ThugLogging.add_behavior_warn("[WScript.Exec ActiveX] Requesting ExitCode")
        return 0

    @property
    def ProcessID(self):
        log.ThugLogging.add_behavior_warn("[WScript.Exec ActiveX] Requesting ProcessID")
        return random.randint(100, 65535)

    @property
    def Status(self):
        log.ThugLogging.add_behavior_warn("[WScript.Exec ActiveX] Requesting Status")
        return 1

    @property
    def StdIn(self):
        log.ThugLogging.add_behavior_warn("[WScript.Exec ActiveX] Requesting StdIn")
        return self._StdIn

    @property
    def StdOut(self):
        log.ThugLogging.add_behavior_warn("[WScript.Exec ActiveX] Requesting StdOut")
        return self._StdOut

    @property
    def StdErr(self):
        log.ThugLogging.add_behavior_warn("[WScript.Exec ActiveX] Requesting StdErr")
        return self._StdErr

    def Terminate(self):
        log.ThugLogging.add_behavior_warn("[WScript.Exec ActiveX] Terminate")
