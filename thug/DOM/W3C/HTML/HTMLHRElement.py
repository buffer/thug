#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .bool_property import bool_property


class HTMLHRElement(HTMLElement):
    align   = attr_property("align")
    noShade = bool_property("noshade")
    size    = attr_property("size")
    width   = attr_property("width")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
