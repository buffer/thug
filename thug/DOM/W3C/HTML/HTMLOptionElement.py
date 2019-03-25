#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import thug_long
from .form_property import form_property


class HTMLOptionElement(HTMLElement):
    defaultSelected = attr_property("selected", bool)
    index           = attr_property("index", thug_long, readonly = True)
    disabled        = attr_property("disabled", bool)
    form            = form_property()
    label           = attr_property("label")
    selected        = False
    value           = attr_property("value")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def text(self):
        return str(self.tag.string) if self.tag.string else ""
