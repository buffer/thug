#!/usr/bin/env python
from __future__ import with_statement

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

import BeautifulSoup
from Element import Element
from Style.ElementCSSInlineStyle import ElementCSSInlineStyle
from attr_property import attr_property
from text_property import text_property


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
        dom = BeautifulSoup.BeautifulSoup(unicode(html))

        # FIXME
        self.tag.contents = []

        for node in dom.contents:
            self.tag.append(node)

