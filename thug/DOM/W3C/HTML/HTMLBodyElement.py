#!/usr/bin/env python

import logging
import bs4 as BeautifulSoup

from six import StringIO

from .HTMLElement import HTMLElement
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLBodyElement(HTMLElement):
    background = attr_property("background")
    bgColor    = attr_property("bgcolor")
    link       = attr_property("link")
    aLink      = attr_property("alink")
    vLink      = attr_property("vlink")
    text       = attr_property("text")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag if tag else doc)

    def __str__(self):
        return "[object HTMLBodyElement]"

    def getInnerHTML(self):
        html = StringIO()

        for tag in self.tag.contents:
            html.write(str(tag))

        return html.getvalue()

    def setInnerHTML(self, html):
        log.HTMLClassifier.classify(log.ThugLogging.url if log.ThugOpts.local else log.last_url_fetched, html)

        self.tag.clear()

        for node in BeautifulSoup.BeautifulSoup(html, "html.parser").contents:
            self.tag.append(node)

            name = getattr(node, 'name', None)
            if name is None:
                continue

            handler = getattr(log.DFT, 'handle_%s' % (name, ), None)
            if handler:
                handler(node)

    innerHTML = property(getInnerHTML, setInnerHTML)
