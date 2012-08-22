# Microsoft XMLHTTP

import os
import urllib
import httplib2
import hashlib
import urlparse
import logging
from DOM.Personality import Personality

log = logging.getLogger("Thug")

def abort(self):
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] abort")
    return 0

def open(self, bstrMethod, bstrUrl, varAsync = True, varUser = None, varPassword = None):
    msg = "[Microsoft XMLHTTP ActiveX] open('%s', '%s', %s" % (bstrMethod, bstrUrl, varAsync is True, )
    if varUser:
        msg = "%s, '%s'" % (msg, varUser, )
    if varPassword:
        msg = "%s, '%s'" % (msg, varPassword, )
    msg = "%s)" % (msg, )
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] %s" % (msg, ))
    
    self.bstrMethod  = bstrMethod
    self.bstrUrl     = bstrUrl
    self.varAsync    = varAsync
    self.varUser     = varUser
    self.varPassword = varPassword

    personality = Personality()
    self.requestHeaders['Cache-Control']   = 'no-cache'
    self.requestHeaders['Accept-Language'] = 'en-US'
    self.requestHeaders['User-Agent']      = personality.userAgent

    return 0

def send(self, varBody = None):
    msg = "send"
    if varBody:
        msg = "%s('%s')" % (msg, str(varBody), )

    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] %s" % (msg, ))

    h = httplib2.Http('/tmp/thug-cache-%s' % (os.getuid(), ),
                       proxy_info = log.ThugOpts.proxy_info,
                       timeout    = 10, 
                       disable_ssl_certificate_validation = True)
    
    _url = urlparse.urlparse(self.bstrUrl)
    if not _url.netloc:
        self.bstrUrl = urlparse.urljoin(self._window.url, self.bstrUrl)

    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] Fetching from URL %s (method: %s)" % (self.bstrUrl, self.bstrMethod, ))
    try:
        response, content = h.request(self.bstrUrl,
                                      self.bstrMethod,
                                      headers = self.requestHeaders, 
                                      body    = varBody)
    except:
        log.ThugLogging.add_behavior_warn('[Microsoft XMLHTTP ActiveX] Fetch failed')
        return

    if response.status == 404:
        log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] FileNotFoundError: %s" % (self.bstrUrl, ))
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()

    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] Saving File: %s" % (filename, ))
    baseDir = log.baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass

    self.responseBody    = content
    self.responseHeaders = response 

def setRequestHeader(self, bstrHeader, bstrValue):
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] setRequestHeaders('%s', '%s')" % (bstrHeader, bstrValue, ))
    self.requestHeaders[bstrHeader] = bstrValue
    return 0

