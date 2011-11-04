
import os
import hashlib
import httplib2
import logging

log = logging.getLogger("Thug.ActiveX")

def LaunchGui(self, arg0, arg1, arg2):
    if len(arg0) > 1500:
        log.warning('EnjoySAP.LaunchGUI overflow in arg0')

def PrepareToPostHTML(self, arg):
    if len(arg) > 1000:
        log.warning('EnjoySAP.PrepareToPostHTML overflow in arg0')

def Comp_Download(self, arg0, arg1):
    log.warning(arg0)
    log.warning(arg1)
    
    url = arg0

    log.warning("[EnjoySAP ActiveX] Fetching from URL %s" % (url, ))

    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.warning('[EnjoySAP ActiveX] Fetch failed')
        return

    if response.status == 404:
        log.warning("FileNotFoundError: %s" % (url, ))
        return 
 
    baseDir = logging.getLogger("Thug").baseDir

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    log.warning("[EnjoySAP ActiveX] Saving File: " + filename)    

    with open(os.path.join(baseDir, filename), 'wb') as fd:
        fd.write(content)
