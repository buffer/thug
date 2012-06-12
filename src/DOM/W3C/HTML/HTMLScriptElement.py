#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .text_property import text_property

class HTMLScriptElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    text            = text_property()
    htmlFor         = None
    event           = None
    charset         = attr_property("charset")
    defer           = attr_property("defer", bool)
    src             = attr_property("src", default = "")
    type            = attr_property("type")

