
import logging

log = logging.getLogger("Thug")


def ShellExecute(self, *args):
    cmdLine = ''

    for arg in args:
        if not arg or len(arg) == 0:
            continue

        cmdLine += str(arg)

    # Attempt to extract some URLs from the command line

    urls = set()

    if 'http' in cmdLine:
        for sep in ("'", '"'):
            offset = cmdLine.find("{}http".format(sep))
            if offset < 0:
                continue

            url = cmdLine[offset + 1:].split("'")
            urls.add(url[0])

    log.ThugLogging.add_behavior_warn('[Shell.Application ActiveX] ShellExecute command: {}'.format(cmdLine))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Shell.Application ActiveX",
                                      "ShellExecute command",
                                      data = {
                                                "command" : cmdLine
                                             },
                                      forward = False)

    for url in urls:
        log.ThugLogging.add_behavior_warn('[Shell.Application ActiveX] URL detected: {}'.format(url))

        try:
            self._window._navigator.fetch(url, redirect_type = "ShellExecute")
        except: # pylint:disable=bare-except
            pass
