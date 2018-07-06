#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .compatibility import thug_long
from .compatibility import thug_maxint


class HTMLInputElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    # defaultValue    = attr_property("value")
    _value          = attr_property("value")
    defaultChecked  = attr_property("checked", bool)

    @property
    def form(self):
        raise NotImplementedError()

    accept          = attr_property("accept")
    accessKey       = attr_property("accesskey")
    align           = attr_property("align")
    alt             = attr_property("alt")
    checked         = attr_property("checked", bool)
    disabled        = attr_property("disabled", bool)
    maxLength       = attr_property("maxlength", thug_long, default = thug_maxint)
    name            = attr_property("name")
    readOnly        = attr_property("readonly", bool)
    size            = attr_property("size", thug_long)
    src             = attr_property("src")
    tabIndex        = attr_property("tabindex", thug_long)
    type            = attr_property("type", default = "text")
    useMap          = attr_property("usermap")

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
