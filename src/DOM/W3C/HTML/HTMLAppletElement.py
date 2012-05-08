#!/usr/bin/env python

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLAppletElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    align           = attr_property("align")
    alt             = attr_property("alt")
    archive         = attr_property("archive")
    code            = attr_property("code")
    codeBase        = attr_property("codebase")
    height          = attr_property("height")
    hspace          = attr_property("hspace", long)
    name            = attr_property("name")
    object          = attr_property("object")
    vspace          = attr_property("vspace", long)
    width           = attr_property("width")

