#!/usr/bin/env python

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

import bs4 as BeautifulSoup
from Element import Element
from Style.ElementCSSInlineStyle import ElementCSSInlineStyle
from .attr_property import attr_property
from .text_property import text_property

class HTMLElement(Element, ElementCSSInlineStyle):
    id              = attr_property("id")
    title           = attr_property("title")
    lang            = attr_property("lang")
    dir             = attr_property("dir")
    className       = attr_property("class")

    @property
    def innerHTML(self):
        if not self.hasChildNodes():
            return ""

        html = StringIO()

        for tag in self.tag.contents:
            html.write(str(tag).strip())

        return html.getvalue()

    @innerHTML.setter
    def innerHTML(self, html):
        # FIXME
        #dom = BeautifulSoup.BeautifulSoup(html)
        dom = BeautifulSoup.BeautifulSoup(unicode(html), "html5lib")
        # FIXME
        self.tag.contents = []

        for node in dom.contents:
            self.tag.append(node)

    # WARNING: NOT DEFINED IN W3C SPECS!
    def focus(self):
        pass

    @property
    def sourceIndex(self):
        return None
