
import logging
log = logging.getLogger("Thug")

def DownloadFile(self, *arg):
    log.ThugLogging.add_behavior_warn('[ZenturiProgramChecker ActiveX] Attack in DownloadFile function')

    log.ThugLogging.add_behavior_warn('[ZenturiProgramChecker ActiveX] Downloading from %s' % (arg[0], ))
    log.ThugLogging.add_behavior_warn("[ZenturiProgramChecker ActiveX] Saving downloaded file as: %s" % (arg[1], ))

    try:
        response, content = self._window._navigator.fetch(arg[0], redirect_type = "ZenturiProgramChecker Exploit")
    except:
        log.ThugLogging.add_behavior_warn('[ZenturiProgramChecker ActiveX] Fetch failed')

def DebugMsgLog(self, *arg):
    log.ThugLogging.add_behavior_warn('[ZenturiProgramChecker ActiveX] Attack in DebugMsgLog function')

def NavigateUrl(self, *arg):
    log.ThugLogging.add_behavior_warn('[ZenturiProgramChecker ActiveX] Attack in NavigateUrl function')

