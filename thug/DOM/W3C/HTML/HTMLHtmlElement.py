#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLHtmlElement(HTMLElement):
    version = attr_property("version")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
