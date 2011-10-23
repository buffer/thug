
import os
import hashlib
import logging
log = logging.getLogger("Thug.ActiveX")

def launch(self, arg):
    log.warning("[Java Deployment Toolkit ActiveX] Launching: %s" % (arg, ))

    tokens = arg.split(' ')
    if tokens[0].lower() != 'http:':
        return

    for token in tokens[1:]:
        if not token.lower().startswith('http'):
            continue
            
        log.warning("[Java Deployment Toolkit ActiveX] Fetching from URL %s" % (token, ))

        try:
            response, content = self._window._navigator.fetch(token)
        except:
            log.warning("[Java Deployment Toolkit ActiveX] Fetch Failed")
            continue

        md5 = hashlib.md5()
        md5.update(content)
        filename = md5.hexdigest()

        log.warning("[Java Deployment Toolkit ActiveX] Saving File: " + filename)
                              
        baseDir = logging.getLogger("Thug").baseDir

        try:
            fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
            os.write(fd, content)
            os.close(fd)
        except:
            pass

