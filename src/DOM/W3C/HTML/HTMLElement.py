#!/usr/bin/env python

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

try:
    from io import StringIO
except ImportError:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

import bs4 as BeautifulSoup
import logging

from Element import Element
from Style.CSS.ElementCSSInlineStyle import ElementCSSInlineStyle
from .attr_property import attr_property
from .text_property import text_property

log = logging.getLogger("Thug")


class HTMLElement(Element, ElementCSSInlineStyle):
    id              = attr_property("id")
    title           = attr_property("title")
    lang            = attr_property("lang")
    dir             = attr_property("dir")
    className       = attr_property("class", default = "")

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

            try:
                p = getattr(self.doc.window.doc.DFT, 'handle_%s' % (name, ), None)
            except:
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
