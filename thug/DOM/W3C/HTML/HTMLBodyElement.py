#!/usr/bin/env python

import logging

import io
import bs4

from .HTMLElement import HTMLElement
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLBodyElement(HTMLElement):
    aLink = attr_property("alink")
    background = attr_property("background")
    bgColor = attr_property("bgcolor")
    link = attr_property("link")
    text = attr_property("text")
    vLink = attr_property("vlink")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag if tag else doc)

    def __str__(self):
        return "[object HTMLBodyElement]"

    def getInnerHTML(self):
        html = io.StringIO()

        for tag in self.tag.contents:
            try:
                html.write(str(tag))
            except Exception as e:  # pragma: no cover,pylint:disable=broad-except
                log.warning("[HTMLBodyElement] innerHTML warning: %s", str(e))

        return html.getvalue()

    def setInnerHTML(self, html):
        log.HTMLClassifier.classify(
            log.ThugLogging.url if log.ThugOpts.local else log.last_url, html
        )

        self.tag.clear()

        for node in bs4.BeautifulSoup(html, "html.parser").contents:
            self.tag.append(node)

            name = getattr(node, "name", None)
            if name is None:
                continue

            handler = getattr(log.DFT, f"handle_{name}", None)
            if handler:
                handler(node)

    innerHTML = property(getInnerHTML, setInnerHTML)
