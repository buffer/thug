#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .text_property import text_property
from .compatibility import thug_long
from .form_property import form_property


class HTMLTextAreaElement(HTMLElement):
    accessKey = attr_property("accesskey")
    cols      = attr_property("cols", thug_long)
    disabled  = attr_property("disabled", bool)
    form      = form_property()
    name      = attr_property("name")
    readOnly  = attr_property("readonly", bool)
    rows      = attr_property("rows", thug_long)
    tabIndex  = attr_property("tabindex", thug_long)
    value     = text_property()

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    defaultValue    = None

    @property
    def type(self):
        return "textarea"

    def focus(self):
        pass

    def blur(self):
        pass

    def select(self):
        pass
