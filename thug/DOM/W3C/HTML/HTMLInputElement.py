#!/usr/bin/env python

import six

from .HTMLElement import HTMLElement
from .attr_property import attr_property
from .bool_property import bool_property
from .form_property import form_property


class HTMLInputElement(HTMLElement):
    accept         = attr_property("accept")
    accessKey      = attr_property("accesskey")
    align          = attr_property("align")
    alt            = attr_property("alt")
    checked        = bool_property("checked")
    defaultChecked = bool_property("checked")
    defaultValue   = bool_property("value")
    disabled       = bool_property("disabled")
    form           = form_property()
    maxLength      = attr_property("maxlength", int, default = six.MAXSIZE)
    name           = attr_property("name")
    readOnly       = bool_property("readonly")
    size           = attr_property("size", int)
    src            = attr_property("src")
    tabIndex       = attr_property("tabindex", int)
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
