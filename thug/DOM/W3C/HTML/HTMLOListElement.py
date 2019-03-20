#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import thug_long


class HTMLOListElement(HTMLElement):
    compact = attr_property("compact", bool)
    start   = attr_property("start", thug_long)
    type    = attr_property("type")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
