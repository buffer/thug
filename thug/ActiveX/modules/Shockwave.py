
import logging

log = logging.getLogger("Thug")


def ShockwaveVersion(self, arg):
    if len(arg) >= 768 * 768:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Shockwave",
                                          "ShockwaveVersion Stack Overflow")
        log.ThugLogging.Shellcode.check_shellcode(arg)
