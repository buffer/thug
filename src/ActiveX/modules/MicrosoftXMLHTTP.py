# Microsoft XMLHTTP

import os
import urllib
import hashlib
import urlparse
import logging

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
    
    self.responseHeaders, self.responseBody = self._window._navigator.fetch(self.bstrUrl,
                                                                            method  = self.bstrMethod,
                                                                            headers = self.requestHeaders,
                                                                            body    = varBody)

def setRequestHeader(self, bstrHeader, bstrValue):
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] setRequestHeaders('%s', '%s')" % (bstrHeader, bstrValue, ))
    self.requestHeaders[bstrHeader] = bstrValue
    return 0

