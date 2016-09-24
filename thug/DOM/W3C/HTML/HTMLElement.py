#!/usr/bin/env python

try:
    from io import StringIO
except ImportError:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

import bs4 as BeautifulSoup
import logging

from thug.DOM.W3C.Element import Element
from thug.DOM.W3C.Style.CSS.ElementCSSInlineStyle import ElementCSSInlineStyle
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLElement(Element, ElementCSSInlineStyle):
    id              = attr_property("id")
    title           = attr_property("title")
    lang            = attr_property("lang")
    dir             = attr_property("dir")
    className       = attr_property("class", default = "")

    def __init__(self, doc, tag):
        Element.__init__(self, doc, tag)
        ElementCSSInlineStyle.__init__(self, doc, tag)

    def getInnerHTML(self):
        if not self.hasChildNodes():
            return ""

        html = StringIO()

        for tag in self.tag.contents:
            html.write(unicode(tag))

        return html.getvalue()

    def setInnerHTML(self, html):
        self.tag.clear()

        soup = BeautifulSoup.BeautifulSoup(html, "html5lib")

        for node in list(soup.head.descendants):
            self.tag.append(node)

            name = getattr(node, 'name', None)
            if name is None:
                continue

            handler = getattr(log.DFT, 'handle_%s' % (name, ), None)
            if handler:
                handler(node)

        for node in list(soup.body.children):
            self.tag.append(node)

            name = getattr(node, 'name', None)
            if name is None:
                continue

            handler = getattr(log.DFT, 'handle_%s' % (name, ), None)
            if handler:
                handler(node)

        #soup.head.unwrap()
        #soup.body.unwrap()
        #soup.html.wrap(self.tag)
        #self.tag.html.unwrap()

        for node in self.tag.descendants:
            name = getattr(node, 'name', None)
            if not name:
                continue

            p = getattr(self.doc.window.doc.DFT, 'handle_%s' % (name, ), None)
            if p is None:
                p = getattr(log.DFT, 'handle_%s' % (name, ), None)

            if p:
                p(node)
            
    innerHTML = property(getInnerHTML, setInnerHTML)

    # WARNING: NOT DEFINED IN W3C SPECS!
    def focus(self):
        pass

    @property
    def sourceIndex(self):
        return None
