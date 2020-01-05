
import re
import logging

log = logging.getLogger("Thug")


def ShellExecute(self, sFile, vArguments = "", vDirectory = "", vOperation = "open", vShow = 1):
    cmdLine = "{} {}".format(sFile, vArguments)
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                      cmdLine.replace("'", '"'))

    log.ThugLogging.add_behavior_warn('[Shell.Application ActiveX] ShellExecute("{}", "{}", "{}", "{}", "{}")'.format(sFile,
                                                                                                                      vArguments,
                                                                                                                      vDirectory,
                                                                                                                      vOperation,
                                                                                                                      vShow))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Shell.Application ActiveX",
                                      "ShellExecute command",
                                      data = {
                                                "sFile"      : sFile,
                                                "vArguments" : vArguments,
                                                "vDirectory" : vDirectory,
                                                "vOperation" : vOperation,
                                                "vShow"      : vShow
                                             },
                                      forward = False)

    for url in urls:
        log.ThugLogging.add_behavior_warn('[Shell.Application ActiveX] URL detected: {}'.format(url))

        try:
            self._window._navigator.fetch(url, redirect_type = "ShellExecute")
        except Exception:
            pass
