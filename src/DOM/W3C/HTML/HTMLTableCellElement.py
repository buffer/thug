#!/usr/bin/env python

from HTMLElement import HTMLElement
from attr_property import attr_property

class HTMLTableCellElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def cellIndex(self):
        raise NotImplementedError()

    abbr            = attr_property("abbr")
    align           = attr_property("align")
    axis            = attr_property("axis")
    bgColor         = attr_property("bgcolor")
    ch              = attr_property("char")
    chOff           = attr_property("charoff")
    colSpan         = attr_property("colspan", long)
    headers         = attr_property("headers")
    height          = attr_property("height")
    noWrap          = attr_property("nowrap", bool)
    rowSpan         = attr_property("rowspan", long)
    scope           = attr_property("scope")
    vAlign          = attr_property("valign")
    width           = attr_property("width")

