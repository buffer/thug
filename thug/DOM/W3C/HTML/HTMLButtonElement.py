#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .bool_property import bool_property
from .form_property import form_property


class HTMLButtonElement(HTMLElement):
    accessKey = attr_property("accesskey")
    disabled  = bool_property("disabled")
    form      = form_property()
    name      = attr_property("name")
    tabIndex  = attr_property("tabindex", int)
    type      = attr_property("type")
    value     = attr_property("value")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
