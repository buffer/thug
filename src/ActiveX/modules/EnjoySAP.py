
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

    #headers = {
    #    'user-agent' : logging.getLogger("Thug").userAgent,
    #}

    #h = httplib2.Http('/tmp/.cache')

    #FIXME: Relative URLs
    #response, content = h.request(arg0, headers = headers)
    response, content = self._window._navigator.fetch(arg0)
    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    log.warning("[*] Saving File: " + filename)
    
    with open(filename, 'wb') as fd:
        fd.write(content)

