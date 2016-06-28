
import logging
log = logging.getLogger("Thug")

def DownloadFile(self, *arg):
    log.ThugLogging.add_behavior_warn('[ZenturiProgramChecker ActiveX] Attack in DownloadFile function')

    log.ThugLogging.add_behavior_warn('[ZenturiProgramChecker ActiveX] Downloading from %s' % (arg[0], ))
    log.ThugLogging.add_behavior_warn("[ZenturiProgramChecker ActiveX] Saving downloaded file as: %s" % (arg[1], ))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "ZenturiProgramChecker ActiveX",
                                      "DownloadFile function",
                                      forward = False,
                                      data = {
                                                "url"     : arg[0],
                                                "filename": arg[1]
                                             }
                                     )

    try:
        self._window._navigator.fetch(arg[0], redirect_type = "ZenturiProgramChecker Exploit")
    except: #pylint:disable=bare-except
        log.ThugLogging.add_behavior_warn('[ZenturiProgramChecker ActiveX] Fetch failed')

def DebugMsgLog(self, *arg):
    log.ThugLogging.add_behavior_warn('[ZenturiProgramChecker ActiveX] Attack in DebugMsgLog function')
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "ZenturiProgramChecker ActiveX",
                                      "Attack in DebugMsgLog function")

def NavigateUrl(self, *arg):
    log.ThugLogging.add_behavior_warn('[ZenturiProgramChecker ActiveX] Attack in NavigateUrl function')
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "ZenturiProgramChecker ActiveX",
                                      "Attack in NavigateUrl function")
