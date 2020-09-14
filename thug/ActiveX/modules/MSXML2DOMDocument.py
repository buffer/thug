
import logging

log = logging.getLogger("Thug")


def definition(self, arg):
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "MSXML2.DOMDocument",
                                      "Microsoft XML Core Services MSXML Uninitialized Memory Corruption",
                                      cve = "CVE-2012-1889")  # pylint:disable=undefined-variable

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2012-1889")
    log.ThugLogging.Shellcode.check_shellcode(arg)
