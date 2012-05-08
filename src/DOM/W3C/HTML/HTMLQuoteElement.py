#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property

class HTMLQuoteElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    cite            = attr_property("cite")

