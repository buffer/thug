#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .text_property import text_property
from .compatibility import thug_long


class HTMLOptionElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def form(self):
        return None

    defaultSelected = attr_property("selected", bool)
    index           = attr_property("index", thug_long, readonly = True)
    disabled        = attr_property("disabled", bool)
    label           = attr_property("label")
    selected        = False
    value           = attr_property("value")

    @property
    def text(self):
        return str(self.tag.string) if self.tag.string else ""
