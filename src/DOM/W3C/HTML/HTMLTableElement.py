#!/usr/bin/env python

from .HTMLElement import HTMLElement
from .attr_property import attr_property

class HTMLTableElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)

    @property
    def caption(self):
        raise NotImplementedError()

    @property
    def tHead(self):
        raise NotImplementedError()

    @property
    def tFoot(self):
        raise NotImplementedError()

    @property
    def rows(self):
        raise NotImplementedError()

    @property
    def tBodies(self):
        raise NotImplementedError()

    align           = attr_property("align")
    bgColor         = attr_property("bgcolor")
    border          = attr_property("border")
    cellPadding     = attr_property("cellpadding")
    cellSpacing     = attr_property("cellspacing")
    frame           = attr_property("frame")
    rules           = attr_property("rules")
    summary         = attr_property("summary")
    width           = attr_property("width")

    def createTHead():
        pass

    def deleteTHead():
        pass

    def createTFoot():
        pass

    def deleteTFoot():
        pass

    def createCaption():
        pass

    def deleteCaption():
        pass

    # Modified in DOM Level 2
    def insertRow(self, index):
        pass

