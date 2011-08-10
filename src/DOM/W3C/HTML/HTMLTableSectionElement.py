#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property


class HTMLTableSectionElement(HTMLElement):
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


