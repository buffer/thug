# Microsoft XMLHTTP

import os
import hashlib
import logging

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

from DOM.W3C import *
import DOM

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
                                                "url"    : str(bstrUrl),
                                                "async"  : str(varAsync)
                                             }
                                     )
    
    self.bstrMethod  = bstrMethod
    self.bstrUrl     = str(bstrUrl)
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
                                                "url"    : str(self.bstrUrl)
                                             }
                                     )

    try:
        response = self._window._navigator.fetch(self.bstrUrl,
                                                 method        = self.bstrMethod,
                                                 headers       = self.requestHeaders,
                                                 body          = varBody,
                                                 redirect_type = "Microsoft XMLHTTP Exploit")
    except:
        log.ThugLogging.add_behavior_warn('[Microsoft XMLHTTP ActiveX] Fetch failed')

    self.responseHeaders = response.headers
    self.responseBody    = response.content

    contenttype = self.responseHeaders.get('content-type', None)
    if contenttype is None:
        return

    if 'text/html' in contenttype:
        doc = w3c.parseString(self.responseBody)

        window = DOM.Window.Window(self.bstrUrl, doc, personality = log.ThugOpts.useragent)
        #window.open(self.bstrUrl)

        dft = DOM.DFT.DFT(window)
        dft.run()
        return

    handler = log.MIMEHandler.get_handler(contenttype)
    if handler:
        handler(url, html)


def setRequestHeader(self, bstrHeader, bstrValue):
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] setRequestHeaders('%s', '%s')" % (bstrHeader, bstrValue, ))
    self.requestHeaders[bstrHeader] = bstrValue
    return 0


def getResponseHeader(self, header):
    body = ""
    if header in self.responseHeaders:
        body = self.responseHeaders[header]

    try:
        self._window._navigator.fetch(self.bstrUrl,
                                      method  = self.bstrMethod,
                                      headers = self.requestHeaders,
                                      body    = body)
    except:
        pass


def getAllResponseHeaders(self):
    body = ""
    for k, v in self.responseHeaders.items():
        body += "%s: %s\r\n" % (k, v, )

    try:
        self._window._navigator.fetch(self.bstrUrl,
                                      method  = self.bstrMethod,
                                      headers = self.requestHeaders,
                                      body    = body)
    except:
        pass
