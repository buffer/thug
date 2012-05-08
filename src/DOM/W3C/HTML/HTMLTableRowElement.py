#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property

class HTMLTableRowElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    # Modified in DOM Level 2
    @property
    def rowIndex(self):
        raise NotImplementedError()

    # Modified in DOM Level 2
    @property
    def sectionRowIndex(self):
        raise NotImplementedError()

    # Modified in DOM Level 2
    @property
    def cells(self):
        raise NotImplementedError()

    align           = attr_property("align")
    bgColor         = attr_property("bgcolor")
    ch              = attr_property("char")
    chOff           = attr_property("charoff")
    vAlign          = attr_property("valign")

    # Modified in DOM Level 2
    def insertCell(self, index):
        pass

    # Modified in DOM Level 2
    def deleteCell(self, index):
        pass

