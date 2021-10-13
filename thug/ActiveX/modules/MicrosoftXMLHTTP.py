# Microsoft XMLHTTP

import logging
# from urllib.parse import urlparse
# from urllib.parse import urlunparse

from lxml.html import builder as E
from lxml.html import tostring

from thug import DOM

log = logging.getLogger("Thug")


def abort(self):
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] abort")
    self.dispatchEvent("abort")
    return 0


def open(self, bstrMethod, bstrUrl, varAsync = True, varUser = None, varPassword = None):  # pylint:disable=redefined-builtin
    # Internet Explorer ignores any \r\n or %0d%0a or whitespace appended to the domain name
    # parsedUrl = urlparse(bstrUrl)
    # netloc = parsedUrl.netloc.strip("\r\n\t")
    # bstrUrl = urlunparse((parsedUrl.scheme,
    #                       netloc,
    #                       parsedUrl.path,
    #                       parsedUrl.params,
    #                       parsedUrl.query,
    #                       parsedUrl.fragment))

    msg = f"[Microsoft XMLHTTP ActiveX] open('{bstrMethod}', '{bstrUrl}', {varAsync is True}"
    if varUser:
        msg = f"{msg}, '{varUser}'"
    if varPassword:
        msg = f"{msg}, '{varPassword}'"
    msg = f"{msg})"

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
        msg = f"{msg}('{str(varBody)}')"

    log.ThugLogging.add_behavior_warn(f"[Microsoft XMLHTTP ActiveX] {msg}")
    log.ThugLogging.add_behavior_warn(f"[Microsoft XMLHTTP ActiveX] Fetching from URL {self.bstrUrl} (method: {self.bstrMethod})")
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
    except Exception: # pylint:disable=broad-except
        log.ThugLogging.add_behavior_warn('[Microsoft XMLHTTP ActiveX] Fetch failed')
        self.dispatchEvent("timeout")
        self.dispatchEvent("error")

    if response is None:
        return 0

    self.status          = response.status_code
    self.responseHeaders = response.headers
    self.responseBody    = response.content
    self.responseText    = response.text
    self.readyState      = 4

    if getattr(log, 'XMLHTTP', None) is None:
        log.XMLHTTP = {}

    log.XMLHTTP['status']          = self.status
    log.XMLHTTP['responseHeaders'] = self.responseHeaders
    log.XMLHTTP['responseBody']    = self.responseBody
    log.XMLHTTP['responseText']    = self.responseText
    log.XMLHTTP['readyState']      = self.readyState

    last_bstrUrl    = log.XMLHTTP.get('last_bstrUrl', None)
    last_bstrMethod = log.XMLHTTP.get('last_bstrMethod', None)

    if last_bstrUrl in (self.bstrUrl, ) and last_bstrMethod in (self.bstrMethod, ): # pragma: no cover
        return 0

    log.XMLHTTP['last_bstrUrl']    = str(self.bstrUrl)
    log.XMLHTTP['last_bstrMethod'] = str(self.bstrMethod)

    if self.mimeType:
        contenttype = self.mimeType
    else:
        contenttype = self.responseHeaders.get('content-type', None)

    if contenttype is None: # pragma: no cover
        return 0

    self.dispatchEvent("load")
    self.dispatchEvent("readystatechange")

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
            html = tostring(E.HTML(E.HEAD(), E.BODY(E.SCRIPT(response.text)))) # pragma: no cover
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


def setTimeouts(self, ResolveTimeout, ConnectTimeout, SendTimeout, ReceiveTimeout): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f"[Microsoft XMLHTTP ActiveX] setTimeouts("
                                      f"{ResolveTimeout}, "
                                      f"{ConnectTimeout}, "
                                      f"{SendTimeout}, "
                                      f"{ReceiveTimeout}")

    return 0

def waitForResponse(self, timeout): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f"[Microsoft XMLHTTP ActiveX] waitForResponse({timeout})")


def setRequestHeader(self, bstrHeader, bstrValue):
    log.ThugLogging.add_behavior_warn(f"[Microsoft XMLHTTP ActiveX] setRequestHeaders('{bstrHeader}', '{bstrValue}')")
    self.requestHeaders[bstrHeader] = bstrValue
    return 0


def getResponseHeader(self, header):
    return self.responseHeaders.get(header, None)


def getAllResponseHeaders(self):
    output = ""
    for k, v in self.responseHeaders.items():
        output += f"{k}: {v}\r\n"

    return output


def overrideMimeType(self, mimetype):
    self.mimeType = mimetype


def addEventListener(self, _type, listener, useCapture = False): # pylint:disable=unused-argument
    if log.ThugOpts.features_logging:
        log.ThugLogging.Features.increase_addeventlistener_count()

    setattr(self, f'on{_type.lower()}', listener)


def removeEventListener(self, _type, listener, useCapture = False): # pylint:disable=unused-argument
    if log.ThugOpts.features_logging:
        log.ThugLogging.Features.increase_removeeventlistener_count()

    _listener = getattr(self, f'on{_type.lower()}', None)
    if _listener is None:
        return

    if _listener in (listener, ):
        delattr(self, f'on{_type.lower()}')


def dispatchEvent(self, evt, pfResult = True): # pylint:disable=unused-argument
    if log.ThugOpts.features_logging:
        log.ThugLogging.Features.increase_dispatchevent_count()

    listener = getattr(self, f'on{evt.lower()}', None)
    if listener is None:
        return

    with self._window.context:
        listener.__call__()
