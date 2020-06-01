
import logging
log = logging.getLogger("Thug")


class SchemeHandler(object):
    def __init__(self):
        pass

    def handle_hcp(self, window, url):
        log.warning('Microsoft Internet Explorer HCP Scheme Detected')

        hcp = url.split('svr=')
        if len(hcp) < 2:
            return

        hcp = hcp[1].split('defer>')
        if len(hcp) < 2:
            return

        hcp = hcp[1].split('</script')

        log.ThugLogging.add_behavior_warn('Microsoft Windows Help Center Malformed Escape Sequences Incorrect Handling',
                                          'CVE-2010-1885')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2010-1885")

        if not hcp or not hcp[0]:
            return

        window.evalScript(hcp[0])

    def handle_res(self, window, url):
        log.warning('Microsoft Internet Explorer RES Scheme Detected')

        try:
            log.URLClassifier.classify(url)
        except Exception: # pragma: no cover
            pass
