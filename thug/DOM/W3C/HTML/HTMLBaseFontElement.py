#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLBaseFontElement(HTMLElement):
    color = attr_property("color")
    face = attr_property("face")
    size = attr_property("size", int)

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
