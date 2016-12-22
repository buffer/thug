#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .text_property import text_property
from .compatibility import thug_long


class HTMLTextAreaElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    defaultValue    = None

    @property
    def form(self):
        pass

    accessKey       = attr_property("accesskey")
    cols            = attr_property("cols", thug_long)
    disabled        = attr_property("disabled", bool)
    name            = attr_property("name")
    readOnly        = attr_property("readonly", bool)
    rows            = attr_property("rows", thug_long)
    tabIndex        = attr_property("tabindex", thug_long)
    value           = text_property()

    @property
    def type(self):
        return "textarea"

    def focus(self):
        pass

    def blur(self):
        pass

    def select(self):
        pass
