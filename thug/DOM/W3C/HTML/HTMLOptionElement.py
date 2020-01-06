#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .bool_property import bool_property
from .form_property import form_property


class HTMLOptionElement(HTMLElement):
    defaultSelected = bool_property("selected")
    index           = attr_property("index", int, readonly = True)
    disabled        = bool_property("disabled")
    form            = form_property()
    label           = attr_property("label")
    selected        = False
    value           = attr_property("value")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def text(self):
        return str(self.tag.string) if self.tag.string else ""
