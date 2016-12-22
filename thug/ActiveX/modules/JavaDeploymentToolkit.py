
import logging

log = logging.getLogger("Thug")


def launch(self, arg):
    log.ThugLogging.add_behavior_warn("[Java Deployment Toolkit ActiveX] Launching: %s" % (arg, ))

    tokens = arg.split(' ')
    if tokens[0].lower() != 'http:':
        return

    for token in tokens[1:]:
        if not token.lower().startswith('http'):
            continue

        log.ThugLogging.add_behavior_warn("[Java Deployment Toolkit ActiveX] Fetching from URL %s" % (token, ))
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Java Deployment Toolkit ActiveX",
                                          "Fetching from URL",
                                          data = {
                                                    "url": token
                                                 },
                                          forward = False)

        try:
            self._window._navigator.fetch(token, redirect_type = "Java Deployment Toolkit Exploit")
        except:  # pylint:disable=bare-except
            log.ThugLogging.add_behavior_warn("[Java Deployment Toolkit ActiveX] Fetch Failed")


def launchApp(self, pJNLP, pEmbedded = None, pVmArgs = None):
    cve_2013_2416 = False
    if len(pJNLP) > 256:
        cve_2013_2416 = True
        log.DFT.check_shellcode(pJNLP)

    if pEmbedded and len(pEmbedded):
        cve_2013_2416 = True
        log.DFT.check_shellcode(pEmbedded)

    if cve_2013_2416:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Java Deployment Toolkit ActiveX",
                                          "Java ActiveX component memory corruption (CVE-2013-2416)",
                                          cve = "CVE-2013-2416",
                                          forward = True)
