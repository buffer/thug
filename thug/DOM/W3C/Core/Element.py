#!/usr/bin/env python

import logging
import random

from urllib.parse import urlsplit

from thug.DOM.W3C.Style.CSS.ElementCSSInlineStyle import ElementCSSInlineStyle

from .DOMException import DOMException
from .Node import Node
from .ClassList import ClassList

log = logging.getLogger("Thug")


FF_STYLES = (
                (27, 'cursor'),
                (19, 'font-size'),
            )

FF_INPUTS = (
                (23, 'range'),
            )


class Element(Node, ElementCSSInlineStyle):
    def __init__(self, doc, tag):
        tag._node = self

        Node.__init__(self, doc, tag)
        ElementCSSInlineStyle.__init__(self, doc, tag)

        self.__init_element_personality()

    def __init_element_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_element_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_element_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_element_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_element_personality_Safari()
            return

    def __init_element_personality_IE(self):
        self.clearAttributes = self._clearAttributes

        if log.ThugOpts.Personality.browserMajorVersion > 7:
            self.querySelectorAll = self._querySelectorAll
            self.querySelector    = self._querySelector

        if log.ThugOpts.Personality.browserMajorVersion > 8:
            self.getElementsByClassName = self._getElementsByClassName
            self.msMatchesSelector      = self._matches
            self.classList              = ClassList(self.tag)

    def __init_element_personality_Firefox(self):
        self.querySelectorAll       = self._querySelectorAll
        self.querySelector          = self._querySelector
        self.mozMatchesSelector     = self._matches
        self.getElementsByClassName = self._getElementsByClassName
        self.classList              = ClassList(self.tag)

        if log.ThugOpts.Personality.browserMajorVersion > 33:
            self.matches = self._matches

    def __init_element_personality_Chrome(self):
        self.querySelectorAll       = self._querySelectorAll
        self.querySelector          = self._querySelector
        self.webkitMatchesSelector  = self._matches
        self.getElementsByClassName = self._getElementsByClassName
        self.classList              = ClassList(self.tag)

        if log.ThugOpts.Personality.browserMajorVersion > 33:
            self.matches = self._matches

    def __init_element_personality_Safari(self):
        self.querySelectorAll       = self._querySelectorAll
        self.querySelector          = self._querySelector
        self.getElementsByClassName = self._getElementsByClassName
        self.classList              = ClassList(self.tag)

        if log.ThugOpts.Personality.browserMajorVersion > 6:
            self.matches = self._matches

        if log.ThugOpts.Personality.browserMajorVersion > 4:
            self.webkitMatchesSelector = self._matches

    def _querySelectorAll(self, selectors):
        from .NodeList import NodeList

        try:
            s = self.tag.select(selectors)
        except Exception: # pragma: no cover,pylint:disable=broad-except
            return NodeList(self.doc, [])

        return NodeList(self.doc, s)

    def _querySelector(self, selectors):
        from .DOMImplementation import DOMImplementation

        try:
            s = self.tag.select(selectors)
        except Exception: # pragma: no cover,pylint:disable=broad-except
            return None

        return DOMImplementation.createHTMLElement(self, s[0]) if s and s[0] else None

    def _matches(self, selector):
        try:
            s = self.tag.select(selector)
        except Exception as e:
            raise DOMException(DOMException.SYNTAX_ERR) from e

        return bool(s)

    def __eq__(self, other): # pragma: no cover
        return Node.__eq__(self, other) and hasattr(other, "tag") and self.tag == other.tag

    def __ne__(self, other): # pragma: no cover
        return not self == other

    def __hash__(self):
        return id(self)

    @property
    def nodeType(self):
        return Node.ELEMENT_NODE

    @property
    def nodeName(self):
        return self.tagName

    @property
    def nodeValue(self):
        return None

    @property
    def clientWidth(self):
        return 800

    @property
    def clientHeight(self):
        return 600

    @property
    def scrollTop(self):
        return random.randint(0, 100)

    @property
    def scrollHeight(self):
        return random.randint(10, 100)

    # Introduced in DOM Level 2
    def hasAttribute(self, name):
        return self.tag.has_attr(name)

    @property
    def tagName(self):
        return self.tag.name.upper()

    def getAttribute(self, name, flags = 0):
        if not isinstance(name, str): # pragma: no cover
            name = str(name)

        return_as_url = False

        if log.ThugOpts.Personality.isIE():
            if log.ThugOpts.Personality.browserMajorVersion < 8:
                # flags parameter is only supported in Internet Explorer earlier
                # than version 8.
                #
                # A value of 0 means that the search is case-insensitive and the
                # returned value does not need to be converted. Other values can
                # be any combination of the following integer constants with the
                # bitwise OR operator:
                #
                # 1   Case-sensitive search
                # 2   Returns the value as a string
                # 4   Returns the value as an URL
                if not flags & 1:
                    name = name.lower()

                if flags & 4:
                    return_as_url = True

        value = self.tag.attrs[name] if name in self.tag.attrs else None

        if isinstance(value, list):
            value = " ".join(value)

        if return_as_url:
            value = log.HTTPSession.normalize_url(self.doc.window, value)

        return value

    def setAttribute(self, name, value):
        from thug.DOM.W3C import w3c
        from thug.DOM.Window import Window
        from thug.DOM.DFT import DFT

        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.increase_setattribute_count()

        if not isinstance(name, str): # pragma: no cover
            name = str(name)

        if log.ThugOpts.Personality.isFirefox():
            if name in ('style', ):
                svalue = value.split('-')

                _value = svalue[0]
                if len(svalue) > 1:
                    _value = f"{_value}{''.join([s.capitalize() for s in svalue[1:]])}"

                for css in [p for p in FF_STYLES if log.ThugOpts.Personality.browserMajorVersion >= p[0]]:
                    if css[1] in value:
                        self.tag.attrs[name] = _value
                return

            if name in ('type', ):
                for _input in [p for p in FF_INPUTS if log.ThugOpts.Personality.browserMajorVersion > p[0]]:
                    if _input[1] in value:
                        self.tag.attrs[name] = value
                return

        self.tag.attrs[name] = value

        if name.lower() in ('src', 'archive'):
            s = urlsplit(value)

            handler = getattr(log.SchemeHandler, f'handle_{s.scheme}', None)
            if handler:
                handler(self.doc.window, value)
                return

            try:
                response = self.doc.window._navigator.fetch(value, redirect_type = "element workaround")
            except Exception: # pylint:disable=broad-except
                return

            if response is None or not response.ok:
                return

            if getattr(response, 'thug_mimehandler_hit', False): # pragma: no cover
                return

            ctype = response.headers.get('content-type', None)
            if ctype and ctype.startswith(('text/html', )):
                doc = w3c.parseString(response.content)
                window = Window(response.url, doc, personality = log.ThugOpts.useragent)
                dft = DFT(window)
                dft.run()

    def removeAttribute(self, name):
        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.increase_removeattribute_count()

        if name in self.tag.attrs:
            del self.tag.attrs[name]

    def _clearAttributes(self):
        from thug.DOM.W3C.Events.HTMLEvent import HTMLEvent
        from thug.DOM.W3C.Events.MouseEvent import MouseEvent

        no_clear = {'id', 'name', 'style', 'value', }
        for events in (HTMLEvent.EventTypes, MouseEvent.EventTypes, ):
            for e in events:
                no_clear.add(f'on{e}')

        names = [name for name in self.tag.attrs if name not in no_clear]
        for name in names:
            self.removeAttribute(name)

    def getAttributeNode(self, name):
        from .Attr import Attr
        return Attr(self.doc, self, name) if name in self.tag.attrs else None

    def setAttributeNode(self, attr):
        self.tag.attrs[attr.name] = attr.value

    def removeAttributeNode(self, attr):
        if attr.name in self.tag.attrs:
            del self.tag.attrs[attr.name]

    def getElementsByTagName(self, tagname):
        from .NodeList import NodeList
        return NodeList(self.doc, self.tag.find_all(tagname))

    def _getElementsByClassName(self, classname):
        from .NodeList import NodeList
        return NodeList(self.doc, self.tag.find_all(class_ = classname))
