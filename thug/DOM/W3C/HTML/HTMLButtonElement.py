#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .form_property import form_property
from .compatibility import thug_long


class HTMLButtonElement(HTMLElement):
    accessKey = attr_property("accesskey")
    disabled  = attr_property("disabled", bool)
    form      = form_property()
    name      = attr_property("name")
    tabIndex  = attr_property("tabindex", thug_long)
    type      = attr_property("type")
    value     = attr_property("value")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
