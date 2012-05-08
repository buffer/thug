#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property

class HTMLTableSectionElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    align           = attr_property("align")
    ch              = attr_property("char")
    chOff           = attr_property("charoff")
    vAlign          = attr_property("valign")

    @property
    def rows(self):
        raise NotImplementedError()

    # Modified in DOM Level 2
    def insertRow(self, index):
        pass

    # Modified in DOM Level 2
    def deleteRow(self, index):
        pass


