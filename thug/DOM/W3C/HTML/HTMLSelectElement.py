#!/usr/bin/env python

from thug.DOM.W3C.Core.DOMException import DOMException

from .HTMLElement import HTMLElement
from .HTMLOptionsCollection import HTMLOptionsCollection
from .attr_property import attr_property
from .bool_property import bool_property


class HTMLSelectElement(HTMLElement):
    selectedIndex = 0
    value         = None
    disabled      = bool_property("disabled")
    multiple      = bool_property("multiple")
    name          = attr_property("name")
    size          = attr_property("size", int)
    tabIndex      = attr_property("tabindex", int)

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
        self._options = [t for t in self.tag.find_all("option")]

    @property
    def type(self):
        return "select-multiple" if self.multiple else "select-one"

    @property
    def length(self):
        return len(self.options)

    @property
    def form(self):
        return None

    @property
    def options(self):
        return HTMLOptionsCollection(self.doc, self._options)

    def add(self, element, before):
        if not before:
            self._options.append(element)
            return

        index = None
        for opt in self._options:
            if before.value in (opt.value, ):
                index = self._options.index(opt)

        if index is None:
            raise DOMException(DOMException.NOT_FOUND_ERR)

        self._options.insert(index, element)

    def remove(self, index):
        if index > len(self._options):
            return

        del self._options[index]

    def blur(self):
        pass

    def focus(self):
        pass
