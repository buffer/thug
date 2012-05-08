#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property

class HTMLBRElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    clear           = attr_property("clear")

