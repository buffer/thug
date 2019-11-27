#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .bool_property import bool_property
from .text_property import text_property
from .form_property import form_property


class HTMLTextAreaElement(HTMLElement):
    accessKey = attr_property("accesskey")
    cols      = attr_property("cols", int)
    disabled  = bool_property("disabled")
    form      = form_property()
    name      = attr_property("name")
    readOnly  = bool_property("readonly")
    rows      = attr_property("rows", int)
    tabIndex  = attr_property("tabindex", int)
    value     = text_property()

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def defaultValue(self):
        return self.value

    @property
    def type(self):
        return "textarea"

    def focus(self):
        pass

    def blur(self):
        pass

    def select(self):
        pass
