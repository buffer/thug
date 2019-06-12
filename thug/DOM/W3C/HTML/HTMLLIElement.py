#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLLIElement(HTMLElement):
    type  = attr_property("type")
    value = attr_property("value", int)

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
