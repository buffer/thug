# Gogago YouTube Video Converter Buffer Overflow
# HTB23012

import logging

log = logging.getLogger("Thug")


def Download(self, arg):
    if len(arg) > 1024:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Gogago YouTube Video Converter ActiveX",
                                          "Buffer Overflow")
