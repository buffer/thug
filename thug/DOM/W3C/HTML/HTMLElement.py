#!/usr/bin/env python

import logging
import random

import io
import bs4

from thug.DOM.W3C.Core.DOMException import DOMException
from thug.DOM.W3C.Core.Element import Element
from .Dataset import Dataset
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLElement(Element):
    id        = attr_property("id")
    title     = attr_property("title")
    lang      = attr_property("lang")
    dir       = attr_property("dir")
    className = attr_property("class", default = "")

    def __init__(self, doc, tag):
        Element.__init__(self, doc, tag)
        self.__init_htmlelement_personality()

    def __init_htmlelement_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_htmlelement_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_htmlelement_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_htmlelement_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_htmlelement_personality_Safari()
            return

    def __init_htmlelement_personality_IE(self):
        if log.ThugOpts.Personality.browserMajorVersion > 10:
            self.dataset = Dataset(self.tag.attrs)

    def __init_htmlelement_personality_Firefox(self):
        if log.ThugOpts.Personality.browserMajorVersion > 5:
            self.dataset = Dataset(self.tag.attrs)

    def __init_htmlelement_personality_Chrome(self):
        if log.ThugOpts.Personality.browserMajorVersion > 7:
            self.dataset = Dataset(self.tag.attrs)

    def __init_htmlelement_personality_Safari(self):
        if log.ThugOpts.Personality.browserMajorVersion > 4:
            self.dataset = Dataset(self.tag.attrs)

    def __getattr__(self, key):
        if key in log.DFT.handled_on_events:
            return None

        if key in log.DFT._on_events:
            return None

        log.info("[HTMLElement] Undefined: %s", key)
        raise AttributeError

    def getInnerHTML(self):
        if not self.hasChildNodes():
            return ""

        html = io.StringIO()

        for tag in self.tag.contents:
            html.write(str(tag))

        return html.getvalue()

    def setInnerHTML(self, html):
        log.HTMLClassifier.classify(log.ThugLogging.url if log.ThugOpts.local else log.last_url, html)

        self.tag.clear()

        for node in bs4.BeautifulSoup(html, "html.parser").contents:
            self.tag.append(node)

            name = getattr(node, 'name', None)
            if name is None:
                continue

            handler = getattr(log.DFT, f'handle_{name}', None)
            if handler:
                handler(node)

    def getOuterHTML(self):
        return str(self.tag)

    innerHTML = property(getInnerHTML, setInnerHTML)
    outerHTML = property(getOuterHTML, setInnerHTML)

    # WARNING: NOT DEFINED IN W3C SPECS!
    def focus(self):
        pass

    @property
    def sourceIndex(self):
        return None

    @property
    def offsetWidth(self):
        return random.randint(10, 100)

    @property
    def offsetTop(self):
        return random.randint(1, 10)

    def insertAdjacentHTML(self, position, text):
        if position not in ('beforebegin', 'afterbegin', 'beforeend', 'afterend', ):
            raise DOMException(DOMException.NOT_SUPPORTED_ERR)

        if position in ('beforebegin', ):
            target = self.tag.parent if self.tag.parent else self.doc.find('body')
            pos    = target.index(self.tag) - 1
        if position in ('afterbegin', ):
            target = self.tag
            pos    = 0
        if position in ('beforeend', ):
            target = self.tag
            pos    = len(list(self.tag.children))
        if position in ('afterend', ):
            target = self.tag.parent if self.tag.parent else self.doc.find('body')
            pos    = target.index(self.tag) + 1

        for node in bs4.BeautifulSoup(text, "html.parser").contents:
            target.insert(pos, node)
            pos += 1
