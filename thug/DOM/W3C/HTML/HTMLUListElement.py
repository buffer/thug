#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLUListElement(HTMLElement):
    compact = attr_property("compact", bool)
    type    = attr_property("type")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
