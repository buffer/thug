#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import thug_long


class HTMLTableColElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    align       = attr_property("align")
    ch          = attr_property("char")
    chOff       = attr_property("charoff")
    span        = attr_property("span", thug_long)
    vAlign      = attr_property("valign")
    width       = attr_property("width")
