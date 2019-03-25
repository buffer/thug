#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .form_property import form_property
from .compatibility import thug_long
from .compatibility import thug_maxint


class HTMLInputElement(HTMLElement):
    accept         = attr_property("accept")
    accessKey      = attr_property("accesskey")
    align          = attr_property("align")
    alt            = attr_property("alt")
    checked        = attr_property("checked", bool)
    defaultChecked = attr_property("checked", bool)
    disabled       = attr_property("disabled", bool)
    form           = form_property()
    maxLength      = attr_property("maxlength", thug_long, default = thug_maxint)
    name           = attr_property("name")
    readOnly       = attr_property("readonly", bool)
    size           = attr_property("size", thug_long)
    src            = attr_property("src")
    tabIndex       = attr_property("tabindex", thug_long)
    type           = attr_property("type", default = "text")
    useMap         = attr_property("usermap")
    _value         = attr_property("value")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    def getValue(self):
        return self._value

    def setValue(self, value):
        self._value = value

    value = property(getValue, setValue)

    def blur(self):
        pass

    def focus(self):
        pass

    def select(self):
        pass

    def click(self):
        pass
