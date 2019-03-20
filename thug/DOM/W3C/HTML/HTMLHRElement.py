#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLHRElement(HTMLElement):
    align   = attr_property("align")
    noShade = attr_property("noshade", bool)
    size    = attr_property("size")
    width   = attr_property("width")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
