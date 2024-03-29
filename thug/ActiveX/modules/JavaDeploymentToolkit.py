import logging

log = logging.getLogger("Thug")


def launch(self, arg):
    log.ThugLogging.add_behavior_warn(
        f"[Java Deployment Toolkit ActiveX] Launching: {arg}"
    )

    tokens = arg.split(" ")
    if tokens[0].lower() != "http:":
        return

    for token in tokens[1:]:
        if not token.lower().startswith("http"):
            continue

        log.ThugLogging.add_behavior_warn(
            f"[Java Deployment Toolkit ActiveX] Fetching from URL {token}"
        )
        log.ThugLogging.log_exploit_event(
            self._window.url,
            "Java Deployment Toolkit ActiveX",
            "Fetching from URL",
            data={"url": token},
            forward=False,
        )

        try:
            self._window._navigator.fetch(
                token, redirect_type="Java Deployment Toolkit Exploit"
            )
        except Exception:  # pylint:disable=broad-except
            log.ThugLogging.add_behavior_warn(
                "[Java Deployment Toolkit ActiveX] Fetch Failed"
            )


def launchApp(self, pJNLP, pEmbedded=None, pVmArgs=None):  # pylint:disable=unused-argument
    cve_2013_2416 = False
    if len(pJNLP) > 32:
        cve_2013_2416 = True
        log.ThugLogging.Shellcode.check_shellcode(pJNLP)

    if pEmbedded:
        cve_2013_2416 = True
        log.ThugLogging.Shellcode.check_shellcode(pEmbedded)

    if cve_2013_2416:
        log.ThugLogging.log_exploit_event(
            self._window.url,
            "Java Deployment Toolkit ActiveX",
            "Java ActiveX component memory corruption (CVE-2013-2416)",
            cve="CVE-2013-2416",
            forward=True,
        )

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2013-2416")
