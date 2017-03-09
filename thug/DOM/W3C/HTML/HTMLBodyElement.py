#!/usr/bin/env python

import bs4 as BeautifulSoup

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLBodyElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    background      = attr_property("background")
    bgColor         = attr_property("bgcolor")
    link            = attr_property("link")
    aLink           = attr_property("alink")
    vLink           = attr_property("vlink")
    text            = attr_property("text")

    def getInnerHTML(self):
        html = unicode()

        for tag in self.tag.contents:
            html += unicode(tag)

        return html

    def setInnerHTML(self, html):
        self.tag.clear()

        for node in BeautifulSoup.BeautifulSoup(html, "html.parser").contents:
            self.tag.append(node)

    innerHTML = property(getInnerHTML, setInnerHTML)

    def __repr__(self):
        return "<HTMLBodyElement at 0x%08X>" % (id(self), )

    def __str__(self):
        body = self.doc.find('body')
        return str(body if body else self.doc)

    def __unicode__(self):
        body = self.doc.find('body')
        return unicode(body if body else self.doc)
