#!/usr/bin/env python

import logging
import six.moves.urllib.parse as urlparse
import six
import bs4

from lxml.html import builder as E
from lxml.html import tostring

from thug.DOM.W3C.Core.Document import Document
from .HTMLBodyElement import HTMLBodyElement
from .text_property import text_property


log = logging.getLogger("Thug")


class HTMLDocument(Document):
    innerHTML = text_property()

    def __str__(self):
        return "[object HTMLDocument]"

    def __init__(self, doc, win = None, referer = None, lastModified = None, cookie = ''):
        Document.__init__(self, doc)

        self._win           = win
        self._body          = HTMLBodyElement(self.doc, self.doc.find('body'))
        self._referer       = referer
        self._lastModified  = lastModified
        self._cookie        = cookie
        self._html          = None
        self._head          = None
        self._currentScript = None
        self._readyState    = "loading"
        self._domain        = urlparse.urlparse(self._win.url).hostname if self._win else ''
        self.current        = None

        self.__init_htmldocument_personality()

    def __init_htmldocument_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_htmldocument_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_htmldocument_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_htmldocument_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_htmldocument_personality_Safari()
            return

    def __init_htmldocument_personality_IE(self):
        from .HTMLDocumentCompatibleInfoCollection import HTMLDocumentCompatibleInfoCollection

        if log.ThugOpts.Personality.browserMajorVersion < 8:
            self._compatible = None
        else:
            self._compatible = HTMLDocumentCompatibleInfoCollection(self.doc, [])

        if log.ThugOpts.Personality.browserMajorVersion > 7:
            self.implementation.createHTMLDocument = self.implementation._createHTMLDocument

        if log.ThugOpts.Personality.browserMajorVersion < 11:
            self.all = self._all
            self.createStyleSheet = self._createStyleSheet

    def __init_htmldocument_personality_Firefox(self):
        self.implementation.createHTMLDocument = self.implementation._createHTMLDocument

    def __init_htmldocument_personality_Chrome(self):
        self.all = self._all
        self.implementation.createHTMLDocument = self.implementation._createHTMLDocument

    def __init_htmldocument_personality_Safari(self):
        self.all = self._all
        self.implementation.createHTMLDocument = self.implementation._createHTMLDocument

    def __getattr__(self, attr):
        if attr in ('_listeners', ):
            return self.tag._listeners # pragma: no cover

        if attr in ('getBoxObjectFor', ) and not log.ThugOpts.Personality.isFirefox():
            raise AttributeError

        if self._win and getattr(self._win, "doc", None):
            if attr in self._win.doc.DFT.handled_on_events:
                return None

            if attr in self._win.doc.DFT._on_events:
                return None

        _attr = self.getElementById(attr)
        if _attr:
            return _attr

        _attr = self.getElementsByName(attr)
        if _attr:
            from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation

            tag = getattr(_attr[0], 'tag', None)
            if tag:
                return DOMImplementation.createHTMLElement(self.doc, tag)

        log.info("[HTMLDocument] Undefined: %s", attr)
        raise AttributeError

    def getWindow(self):
        return self._win

    def setWindow(self, win):
        self._win = win

    window = property(getWindow, setWindow)

    @property
    def body(self):
        return self._body

    @property
    def tag(self):
        return self

    @property
    def _node(self):
        return self # pragma: no cover

    @property
    def parentNode(self):
        return None

    @property
    def referrer(self):
        last_url = getattr(log, 'last_url', None)
        if last_url:
            return last_url

        if self._referer:
            return str(self._referer) # pragma: no cover

        return ""

    @property
    def anchors(self):
        from .HTMLCollection import HTMLCollection

        nodes = [f for f in self.doc.find_all('a') if 'name' in f.attrs and f.attrs['name']]
        return HTMLCollection(self.doc, nodes)

    @property
    def applets(self):
        from .HTMLCollection import HTMLCollection

        applets = [f for f in self.doc.find_all('applet')]
        objects = [f for f in self.doc.find_all('object') if 'type' in f.attrs and 'applet' in f.attrs['type']]
        return HTMLCollection(self.doc, applets + objects)

    @property
    def forms(self):
        from .HTMLCollection import HTMLCollection

        nodes = [f for f in self.doc.find_all('form')]
        return HTMLCollection(self.doc, nodes)

    @property
    def images(self):
        from .HTMLCollection import HTMLCollection

        nodes = [f for f in self.doc.find_all('img')]
        return HTMLCollection(self.doc, nodes)

    @property
    def links(self):
        from .HTMLCollection import HTMLCollection

        nodes = [f for f in self.doc.find_all(['a', 'area']) if 'href' in f.attrs and f.attrs['href']]
        return HTMLCollection(self.doc, nodes)

    @property
    def styleSheets(self):
        from .HTMLCollection import HTMLCollection

        nodes = [f for f in self.doc.find_all('style')]
        return HTMLCollection(self.doc, nodes)

    def getTitle(self):
        title = self.head.tag.find('title')
        return str(title.string) if title else ""

    def setTitle(self, value):
        title = self.head.tag.find('title')

        if title:
            title.string = value
            return

        title = E.TITLE(value)
        tag   = bs4.BeautifulSoup(tostring(title), "html.parser")
        self.head.tag.append(tag)

    title = property(getTitle, setTitle)

    @property
    def lastModified(self):
        return self._lastModified

    def getCookie(self):
        if not log.HTTPSession or not log.HTTPSession.cookies:
            return self._cookie

        items = ["{}={}".format(n, v) for n, v in log.HTTPSession.cookies.items()]
        return "; ".join(items)

    def setCookie(self, value):
        item = value.split()[0]
        k, v = item.split('=')
        log.HTTPSession.set_cookies(k, v)

    cookie = property(getCookie, setCookie)

    def getDomain(self):
        return self._domain

    def setDomain(self, domain):
        self._domain = domain

    domain = property(getDomain, setDomain)

    @property
    def URL(self):
        return self._win.url if self._win else ''

    @property
    def documentElement(self):
        from .HTMLHtmlElement import HTMLHtmlElement

        html = self.doc.find('html')
        return HTMLHtmlElement(self, html if html else self.doc)

    @property
    def readyState(self):
        return self._readyState

    @property
    def compatMode(self):
        return "CSS1Compat"

    @property
    def head(self):
        from .HTMLHeadElement import HTMLHeadElement

        if self._head:
            return self._head

        tag = self.doc.find('head')
        if not tag:
            head = E.HEAD()
            tag  = bs4.BeautifulSoup(tostring(head), "html.parser")

        self._head = HTMLHeadElement(self.doc, tag)
        return self._head

    def getCompatible(self):
        return self._compatible

    def setCompatible(self, compatible):
        from .HTMLDocumentCompatibleInfo import HTMLDocumentCompatibleInfo
        from .HTMLDocumentCompatibleInfoCollection import HTMLDocumentCompatibleInfoCollection

        _compatibles = list()

        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion >= 8:
            for s in compatible.split(';'):
                try:
                    (useragent, version) = s.split('=')
                except ValueError: # pragma: no cover
                    # Ignore the http-equiv X-UA-Compatible content if its
                    # format is not correct
                    return

                for v in version.split(','):
                    p = HTMLDocumentCompatibleInfo(useragent, v)
                    _compatibles.append(p)

            self._compatible = HTMLDocumentCompatibleInfoCollection(self.doc, _compatibles)

    compatible = property(getCompatible, setCompatible)

    @property
    def documentMode(self):
        major = log.ThugOpts.Personality.browserMajorVersion

        if major < 8:
            return 7 if self.compatMode in ("CSS1Compat", ) else 5

        self.window.doc.DFT.force_handle_meta_x_ua_compatible()

        engine = 0

        for index in range(self.compatible.length):
            item = self.compatible.item(index)
            if not item.userAgent.lower() in ("ie", ):
                continue

            _version = item.version.lower()
            if _version in ('edge', ):
                engine = major
                break

            mode_version = _version

            if _version.startswith('emulateie'):
                mode_version = _version.split("emulateie")[1]

            try:
                mode_version = int(mode_version)
            except ValueError: # pragma: no cover
                continue

            if mode_version not in (5, 7, 8, 9, 10): # pragma: no cover
                continue

            if mode_version <= major and mode_version >= engine:
                engine = mode_version

        if not engine:
            engine = min(major, 10)

        return engine

    def open(self, mimetype = 'text/html', historyPosition = "replace"):
        self.doc = bs4.BeautifulSoup("", "html5lib")
        return self

    def close(self):
        if self._html is None:
            return

        html = "".join(self._html)
        self._html = None

        self.doc = log.HTMLInspector.run(html, "html5lib")

    def write(self, html):
        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.increase_document_write_count()

        if isinstance(html, six.integer_types):
            html = str(html)

        log.HTMLClassifier.classify(log.ThugLogging.url if log.ThugOpts.local else self.URL, html)

        if self._html is None:
            self._html = list()

        self._html.append(html)

        tag  = self.current
        body = self.doc.find('body')

        if tag.parent is None:
            parent = body # pragma: no cover
        else:
            parent = body if body and tag.parent.name in ('html', ) else tag.parent

        soup = log.HTMLInspector.run(html, "html.parser")

        for tag in soup.contents:
            if isinstance(tag, bs4.NavigableString):
                child = list(parent.children)[-1]

                if isinstance(child, bs4.NavigableString):
                    child.string.replace_with(child.string + tag)
                if isinstance(child, bs4.Tag):
                    child.append(tag)

            if isinstance(tag, bs4.Tag):
                parent.insert(len(parent.contents), tag)

            name = getattr(tag, "name", None)
            if name in (None, ):
                continue

            try:
                handler = getattr(self._win.doc.DFT, "handle_%s" % (name, ), None)
            except Exception: # pragma: no cover
                handler = getattr(log.DFT, "handle_%s" % (name, ), None)

            if handler:
                handler(tag)

        log.HTMLClassifier.classify(log.ThugLogging.url if log.ThugOpts.local else self.URL, str(self.tag))

        _html = "".join(self._html)
        if html == _html:
            return

        soup = log.HTMLInspector.run(html, "html.parser")

        for tag in soup.contents:
            name = getattr(tag, "name", None)
            if name in ("script", None, ):
                continue

            try:
                handler = getattr(self._win.doc.DFT, "handle_%s" % (name, ), None)
            except Exception: # pragma: no cover
                handler = getattr(log.DFT, "handle_%s" % (name, ), None)

            if handler:
                handler(tag)

    def writeln(self, text):
        self.write(text + "\n")

    def getElementsByName(self, elementName):
        from .HTMLCollection import HTMLCollection

        tags = self.doc.find_all(attrs = {'name': elementName})
        return HTMLCollection(self.doc, tags)

    @property
    def _all(self):
        from .HTMLAllCollection import HTMLAllCollection

        s = [p for p in self.doc.find_all(text = False)]
        return HTMLAllCollection(self.doc, s)

    @property
    def scripts(self):
        from .HTMLAllCollection import HTMLAllCollection

        s = [p for p in self.current.find_all_previous('script')]
        s.append(self.current)

        return HTMLAllCollection(self.doc, s)

    @property
    def currentScript(self):
        from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation

        if self._currentScript:
            return self._currentScript # pragma: no cover

        return DOMImplementation.createHTMLElement(self.doc, self.current) if self.current else None

    def _createStyleSheet(self, URL = None, index = None):
        # Creates a styleSheet object and inserts it into the current document.
        # The createStyleSheet method is only supported by Internet Explorer.
        # In other browsers, use the createElement method to create a new link
        # or style element, and the insertBefore or appendChild method to insert
        # it into the document.
        #
        # URL Optional. String that specifies the URL of a style file. If an
        # URL is specified, a new link element is inserted into the current
        # document that imports the style file. If this parameter is not specified
        # or an empty string is set, then an empty style element is inserted into
        # the current document.
        #
        # index Optional. Integer that specifies the position of the new styleSheet
        # object in the styleSheets collection of the document. This parameter
        # also has effect on the source position of the inserted link or style
        # element. If this parameter is not specified, the new styleSheet object
        # is inserted at the end of the styleSheets collection and the new link or
        # style element is inserted after the other link and style elements in
        # source order.

        _type = 'style' if not URL else 'link'

        obj = self.createElement(_type)
        if _type in ('link', ):
            obj.href = URL
            obj.rel = "stylesheet"

        head = self.getElementsByTagName("head")[0]
        if head is None:
            return obj

        if index is None:
            head.appendChild(obj)
            return obj

        length  = len(head.childNodes)
        matches = 0
        pos     = 0

        while pos < length:
            if head.childNodes[pos].tagName.lower() in (_type, ):
                matches += 1

            if matches > index:
                head.insertBefore(obj, head.childNodes[pos])
                break

            pos += 1

        if matches <= index:
            head.appendChild(obj)

        return obj
