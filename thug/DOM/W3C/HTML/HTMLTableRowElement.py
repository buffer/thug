#!/usr/bin/env python

import logging
from thug.DOM.W3C.Core.DOMException import DOMException
from .HTMLElement import HTMLElement
from .HTMLCollection import HTMLCollection
from .HTMLTableCellElement import HTMLTableCellElement
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLTableRowElement(HTMLElement):
    align   = attr_property("align")
    bgColor = attr_property("bgcolor")
    ch      = attr_property("char")
    chOff   = attr_property("charoff")
    vAlign  = attr_property("valign")

    def __init__(self, doc, tag, table = None, section = None):
        HTMLElement.__init__(self, doc, tag)
        self._table   = table
        self._section = section
        self._cells   = HTMLCollection(doc, [])

    # Modified in DOM Level 2
    @property
    def rowIndex(self):
        if not self._table:
            return None # pragma: no cover

        index = 0

        while index < len(self._table.rows):
            if id(self._table.rows.item(index)) == id(self):
                return index

            index += 1

        return None # pragma: no cover

    # Modified in DOM Level 2
    @property
    def sectionRowIndex(self):
        if not self._section:
            return 0 # pragma: no cover

        index = 0

        while index < len(self._section.rows):
            if id(self._section.rows.item(index)) == id(self):
                return index

            index += 1

        return None # pragma: no cover

    # Modified in DOM Level 2
    @property
    def cells(self):
        return self._cells

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
