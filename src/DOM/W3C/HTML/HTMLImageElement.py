#!/usr/bin/env python

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLImageElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    align           = attr_property("align")
    alt             = attr_property("alt")
    border          = attr_property("border")
    height          = attr_property("height", long)
    hspace          = attr_property("hspace", long)
    isMap           = attr_property("ismap", bool)
    longDesc        = attr_property("longdesc")
    # Removed in DOM Level 2
    #lowSrc          = attr_property("lowsrc")
    name            = attr_property("name")
    src             = attr_property("src")
    useMap          = attr_property("usemap")
    vspace          = attr_property("vspace", long)
    width           = attr_property("width", long)

