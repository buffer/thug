# Microsoft XMLHTTP

import os
import hashlib
import logging

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse


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
    log.ThugLogging.add_behavior_warn(msg)
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Microsoft XMLHTTP ActiveX",
                                      "Open",
                                      forward = False,
                                      data = {
                                                "method" : bstrMethod,
                                                "url"    : bstrUrl,
                                                "async"  : str(varAsync)
                                             }
                                     )
    
    self.bstrMethod  = bstrMethod
    self.bstrUrl     = bstrUrl
    self.varAsync    = varAsync
    self.varUser     = varUser
    self.varPassword = varPassword

    return 0

def send(self, varBody = None):
    msg = "send"
    if varBody:
        msg = "%s('%s')" % (msg, str(varBody), )

    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] %s" % (msg, ))
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] Fetching from URL %s (method: %s)" % (self.bstrUrl, self.bstrMethod, ))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Microsoft XMLHTTP ActiveX",
                                      "Send",
                                      forward = False,
                                      data = {
                                                "method" : self.bstrMethod,
                                                "url" : self.bstrUrl
                                             }
                                     )

    try:
        self.responseHeaders, self.responseBody = self._window._navigator.fetch(self.bstrUrl,
                                                                                method       = self.bstrMethod,
                                                                                headers      = self.requestHeaders,
                                                                                body         = varBody,
                                                                                redirect_type = "Microsoft XMLHTTP Exploit")
    except:
        log.ThugLogging.add_behavior_warn('[Microsoft XMLHTTP ActiveX] Fetch failed')

def setRequestHeader(self, bstrHeader, bstrValue):
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] setRequestHeaders('%s', '%s')" % (bstrHeader, bstrValue, ))
    self.requestHeaders[bstrHeader] = bstrValue
    return 0

