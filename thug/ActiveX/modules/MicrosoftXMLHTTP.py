# Microsoft XMLHTTP

import logging
# import six.moves.urllib.parse as urlparse

from lxml.html import builder as E
from lxml.html import tostring

import thug.DOM as DOM

log = logging.getLogger("Thug")


def abort(self):
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] abort")
    self.dispatchEvent("abort")
    return 0


def open(self, bstrMethod, bstrUrl, varAsync = True, varUser = None, varPassword = None):  # pylint:disable=redefined-builtin
    # Internet Explorer ignores any \r\n or %0d%0a or whitespace appended to the domain name
    # parsedUrl = urlparse.urlparse(bstrUrl)
    # netloc = parsedUrl.netloc.strip("\r\n\t")
    # bstrUrl = urlparse.urlunparse((parsedUrl.scheme, netloc, parsedUrl.path, parsedUrl.params, parsedUrl.query, parsedUrl.fragment))

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
                                                "method" : str(bstrMethod),
                                                "url"    : str(bstrUrl),
                                                "async"  : str(varAsync)
                                             }
                                     )

    self.bstrMethod  = str(bstrMethod)
    self.bstrUrl     = str(bstrUrl)
    self.varAsync    = varAsync
    self.varUser     = varUser
    self.varPassword = varPassword
    self.readyState  = 4
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

    response = None

    self.dispatchEvent("loadstart")

    try:
        response = self._window._navigator.fetch(self.bstrUrl,
                                                 method        = self.bstrMethod,
                                                 headers       = self.requestHeaders,
                                                 body          = varBody,
                                                 redirect_type = "Microsoft XMLHTTP")
    except Exception:
        log.ThugLogging.add_behavior_warn('[Microsoft XMLHTTP ActiveX] Fetch failed')
        self.dispatchEvent("timeout")
        self.dispatchEvent("error")

    if response is None:
        return 0

    self.dispatchEvent("readystatechange")

    self.status          = response.status_code
    self.responseHeaders = response.headers
    self.responseBody    = response.content
    self.responseText    = response.text
    self.readyState      = 4

    if getattr(log, 'XMLHTTP', None) is None:
        log.XMLHTTP = dict()

    last_bstrUrl    = log.XMLHTTP.get('last_bstrUrl', None)
    last_bstrMethod = log.XMLHTTP.get('last_bstrMethod', None)

    if last_bstrUrl in (self.bstrUrl, ) and last_bstrMethod in (self.bstrMethod, ):
        return 0

    log.XMLHTTP['last_bstrUrl']    = str(self.bstrUrl)
    log.XMLHTTP['last_bstrMethod'] = str(self.bstrMethod)

    if self.mimeType:
        contenttype = self.mimeType
    else:
        contenttype = self.responseHeaders.get('content-type', None)

    if contenttype is None:
        return 0

    self.dispatchEvent("load")

    if 'javascript' in contenttype:
        html = tostring(E.HTML(E.HEAD(), E.BODY(E.SCRIPT(response.text))))

        doc = DOM.W3C.w3c.parseString(html)
        window = DOM.Window.Window(self.bstrUrl, doc, personality = log.ThugOpts.useragent)

        dft = DOM.DFT.DFT(window)
        dft.run()
        return 0

    if 'text/html' in contenttype:
        tags = ('<html', '<body', '<head', '<script')

        if not any(tag in response.text.lower() for tag in tags):
            html = tostring(E.HTML(E.HEAD(), E.BODY(E.SCRIPT(response.text))))
        else:
            html = response.text

        doc = DOM.W3C.w3c.parseString(html)
        window = DOM.Window.Window(self.bstrUrl, doc, personality = log.ThugOpts.useragent)
        dft = DOM.DFT.DFT(window)
        dft.run()
        return 0

    handler = log.MIMEHandler.get_handler(contenttype)
    if handler:
        handler(self.bstrUrl, self.responseBody)

    return 0


def setRequestHeader(self, bstrHeader, bstrValue):
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] setRequestHeaders('%s', '%s')" % (bstrHeader, bstrValue, ))
    self.requestHeaders[bstrHeader] = bstrValue
    return 0


def getResponseHeader(self, header):
    return self.responseHeaders.get(header, None)


def getAllResponseHeaders(self):
    output = ""
    for k, v in self.responseHeaders.items():
        output += "%s: %s\r\n" % (k, v, )

    return output


def overrideMimeType(self, mimetype):
    self.mimeType = mimetype


def addEventListener(self, _type, listener, useCapture = False):
    if log.ThugOpts.features_logging:
        log.ThugLogging.Features.increase_addeventlistener_count()

    setattr(self, 'on%s' % (_type.lower(), ), listener)


def removeEventListener(self, _type, listener, useCapture = False):
    if log.ThugOpts.features_logging:
        log.ThugLogging.Features.increase_removeeventlistener_count()

    _listener = getattr(self, 'on%s' % (_type.lower(), ), None)
    if _listener is None:
        return

    if _listener in (listener, ):
        delattr(self, 'on%s' % (_type.lower(), ))


def dispatchEvent(self, evt, pfResult = True):
    if log.ThugOpts.features_logging:
        log.ThugLogging.Features.increase_dispatchevent_count()

    listener = getattr(self, 'on%s' % (evt.lower(), ), None)
    if listener is None:
        return

    with self._window.context:
        listener.__call__()
