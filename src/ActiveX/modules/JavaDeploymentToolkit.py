
import os
import hashlib
import logging
log = logging.getLogger("Thug")

def launch(self, arg):
    log.MAEC.add_behavior_warn("[Java Deployment Toolkit ActiveX] Launching: %s" % (arg, ))

    tokens = arg.split(' ')
    if tokens[0].lower() != 'http:':
        return

    for token in tokens[1:]:
        if not token.lower().startswith('http'):
            continue
            
        log.MAEC.add_behavior_warn("[Java Deployment Toolkit ActiveX] Fetching from URL %s" % (token, ))

        try:
            response, content = self._window._navigator.fetch(token)
        except:
            log.MAEC.add_behavior_warn("[Java Deployment Toolkit ActiveX] Fetch Failed")
            continue

        if response.status == 404:
            log.MAEC.add_behavior_warn("[Java Deployment Toolkit ActiveX] FileNotFoundError: %s" % (url, ))
            continue 

        md5 = hashlib.md5()
        md5.update(content)
        filename = md5.hexdigest()

        log.MAEC.add_behavior_warn("[Java Deployment Toolkit ActiveX] Saving File: " + filename)
                              
        baseDir = log.baseDir

        try:
            fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
            os.write(fd, content)
            os.close(fd)
        except:
            pass

