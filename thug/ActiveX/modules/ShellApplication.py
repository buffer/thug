
import logging

log = logging.getLogger("Thug")


def ShellExecute(self, sFile, vArguments = "", vDirectory = "", vOperation = "open", vShow = 1):
    cmdLine = ''

    # Attempt to extract some URLs from the command line
    urls = set()

    if 'http' in sFile:
        for sep in ("'", '"'):
            offset = cmdLine.find("{}http".format(sep))
            if offset < 0:
                continue

            url = cmdLine[offset + 1:].split("'")
            urls.add(url[0])

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
        except:  # pylint:disable=bare-except
            pass
