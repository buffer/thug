#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property


class HTMLStyleElement(HTMLElement):
    disabled = False
    media    = attr_property("media")
    type     = attr_property("type")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
