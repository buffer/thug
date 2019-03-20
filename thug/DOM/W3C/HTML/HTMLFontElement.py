#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLFontElement(HTMLElement):
    color = attr_property("color")
    face  = attr_property("face")
    size  = attr_property("size")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
