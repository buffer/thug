#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .bool_property import bool_property


class HTMLUListElement(HTMLElement):
    compact = bool_property("compact")
    type    = attr_property("type")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
