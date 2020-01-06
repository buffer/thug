#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .bool_property import bool_property


class HTMLOListElement(HTMLElement):
    compact = bool_property("compact")
    start   = attr_property("start", int)
    type    = attr_property("type")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
