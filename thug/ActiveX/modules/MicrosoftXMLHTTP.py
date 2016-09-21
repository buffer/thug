# Microsoft XMLHTTP

import logging

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

import thug.DOM as DOM

log = logging.getLogger("Thug")


def abort(self):
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] abort")
    return 0


def open(self, bstrMethod, bstrUrl, varAsync = True, varUser = None, varPassword = None): #pylint:disable=redefined-builtin
    # Internet Explorer ignores any \r\n or %0d%0a or whitespace appended to the domain name
    parsedUrl = urlparse.urlparse(bstrUrl)
    netloc = parsedUrl.netloc.strip("\r\n\t")
    bstrUrl = urlparse.urlunparse((parsedUrl.scheme, netloc, parsedUrl.path, parsedUrl.params, parsedUrl.query, parsedUrl.fragment))

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
    self.readyState  = 4

    if self.onreadystatechange:
        with self._window.context as ctx: #pylint:disable=unused-variable
            self.onreadystatechange.__call__()

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
    except: #pylint:disable=bare-except
        log.ThugLogging.add_behavior_warn('[Microsoft XMLHTTP ActiveX] Fetch failed')

    if response is None:
        return

    self.status          = response.status_code
    self.responseHeaders = response.headers
    self.responseBody    = response.content
    self.readyState      = 4

    contenttype = self.responseHeaders.get('content-type', None)
    if contenttype is None:
        return

    if 'text/html' in contenttype:
        doc = DOM.W3C.w3c.parseString(self.responseBody)

        window = DOM.Window.Window(self.bstrUrl, doc, personality = log.ThugOpts.useragent)
        #window.open(self.bstrUrl)

        dft = DOM.DFT.DFT(window)
        dft.run()
        return

    handler = log.MIMEHandler.get_handler(contenttype)
    if handler:
        handler(self.bstrUrl, self.responseBody)

    if self.onreadystatechange:
        with DOM.DFT.context as ctx:
            ctx.eval(self.onreadystatechange)


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
    except: #pylint:disable=bare-except
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
    except: #pylint:disable=bare-except
        pass
