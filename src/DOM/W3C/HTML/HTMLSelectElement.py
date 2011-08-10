#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property


class HTMLSelectElement(HTMLElement):
    @property
    def type(self):
        raise NotImplementedError()

    selectedIndex = 0
    value         = None

    @property
    def length(self):
        raise NotImplementedError()

    @property
    def form(self):
        raise NotImplementedError()

    @property
    def options(self):
        raise NotImplementedError()

    disabled        = attr_property("disabled", bool)
    multiple        = attr_property("multiple", bool)
    name            = attr_property("name")
    size            = attr_property("size", long)
    tabIndex        = attr_property("tabindex", long)

    def add(self, element, before):
        raise NotImplementedError()

    def remove(self, index):
        raise NotImplementedError()

    def blur(self):
        raise NotImplementedError()

    def focus(self):
        raise NotImplementedError()


