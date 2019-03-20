#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLParagraphElement(HTMLElement):
    align = attr_property("align")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
