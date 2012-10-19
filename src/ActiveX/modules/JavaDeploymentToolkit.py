
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

        try:
            response, content = self._window._navigator.fetch(token)
        except:
            log.ThugLogging.add_behavior_warn("[Java Deployment Toolkit ActiveX] Fetch Failed")
