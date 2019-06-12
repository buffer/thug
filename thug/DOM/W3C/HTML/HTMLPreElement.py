#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLPreElement(HTMLElement):
    width = attr_property("width", int)

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
