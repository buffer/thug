
import os
import hashlib
import httplib2
import logging

log = logging.getLogger("Thug")

def LaunchGui(self, arg0, arg1, arg2):
    if len(arg0) > 1500:
        log.MAEC.add_behavior_warn('[EnjoySAP ActiveX] LaunchGUI overflow in arg0')

def PrepareToPostHTML(self, arg):
    if len(arg) > 1000:
        log.MAEC.add_behavior_warn('[EnjoySAP ActiveX] PrepareToPostHTML overflow in arg0')

def Comp_Download(self, arg0, arg1):
    log.warning(arg0)
    log.warning(arg1)
    
    url = arg0

    log.MAEC.add_behavior_warn("[EnjoySAP ActiveX] Fetching from URL %s" % (url, ))

    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.MAEC.add_behavior_warn('[EnjoySAP ActiveX] Fetch failed')
        return

    if response.status == 404:
        log.MAEC.add_behavior_warn("[EnjoySAP ActiveX] FileNotFoundError: %s" % (url, ))
        return 
 
    baseDir = log.baseDir

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    log.MAEC.add_behavior_warn("[EnjoySAP ActiveX] Saving File: " + filename)    

    with open(os.path.join(baseDir, filename), 'wb') as fd:
        fd.write(content)
