#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import thug_long


class HTMLImageElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    align           = attr_property("align")
    alt             = attr_property("alt")
    border          = attr_property("border")
    height          = attr_property("height", thug_long)
    hspace          = attr_property("hspace", thug_long)
    isMap           = attr_property("ismap", bool)
    longDesc        = attr_property("longdesc")
    # Removed in DOM Level 2
    # lowSrc          = attr_property("lowsrc")
    name            = attr_property("name")
    src             = attr_property("src")
    useMap          = attr_property("usemap")
    vspace          = attr_property("vspace", thug_long)
    width           = attr_property("width", thug_long)

    @property
    def complete(self):
        return True
