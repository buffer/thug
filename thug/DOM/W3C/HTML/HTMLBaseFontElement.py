#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import thug_long


class HTMLBaseFontElement(HTMLElement):
    color = attr_property("color")
    face  = attr_property("face")
    size  = attr_property("size", thug_long)

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
