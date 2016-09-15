#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import thug_long

class HTMLLIElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    type            = attr_property("type")
    value           = attr_property("value", thug_long)
