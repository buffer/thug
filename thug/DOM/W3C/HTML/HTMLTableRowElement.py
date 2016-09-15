#!/usr/bin/env python

import logging
from thug.DOM.W3C.DOMException import DOMException
from .HTMLElement import HTMLElement
from .HTMLCollection import HTMLCollection
from .HTMLTableCellElement import HTMLTableCellElement
from .attr_property import attr_property

log = logging.getLogger("Thug")

class HTMLTableRowElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
        self._cells = HTMLCollection(doc, list())

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
        return self._cells

    align           = attr_property("align")
    bgColor         = attr_property("bgcolor")
    ch              = attr_property("char")
    chOff           = attr_property("charoff")
    vAlign          = attr_property("valign")

    # Modified in DOM Level 2
    def insertCell(self, index = None):
        # `index' specifies the position of the row to insert (starts at 0).
        # The value of -1 can also be used; which result in that the new row
        # will be inserted at the last position. This parameter is required
        # in Firefox and Opera, but optional in Internet Explorer, Chrome and
        # Safari. If this parameter is omitted, insertRow() inserts a new row
        # at the last position in IE and at the first position in Chrome and
        # Safari.
        if index is None:
            if log.ThugOpts.Personality.isIE():
                index = -1
            if log.ThugOpts.Personality.isChrome() or log.ThugOpts.Personality.isSafari():
                index = 0

        cell = HTMLTableCellElement(self.doc, self.tag, index)

        if index in (-1, len(self._cells), ):
            self.cells.nodes.append(cell)
        else:
            self.cells.nodes.insert(index, cell)

        return cell

    # Modified in DOM Level 2
    def deleteCell(self, index):
        if index < -1 or index >= len(self.cells.nodes):
            raise DOMException(DOMException.INDEX_SIZE_ERR)

        del self.cells.nodes[index]
