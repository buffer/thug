#!/usr/bin/env python

import logging
import bs4 as BeautifulSoup

from thug.DOM.W3C.Core.DOMException import DOMException

from .HTMLElement import HTMLElement
from .HTMLCollection import HTMLCollection
from .HTMLTableRowElement import HTMLTableRowElement
from .HTMLTableSectionElement import HTMLTableSectionElement
from .HTMLTableCaptionElement import HTMLTableCaptionElement
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLTableElement(HTMLElement):
    align       = attr_property("align")
    bgColor     = attr_property("bgcolor")
    border      = attr_property("border")
    cellPadding = attr_property("cellpadding")
    cellSpacing = attr_property("cellspacing")
    frame       = attr_property("frame")
    rules       = attr_property("rules")
    summary     = attr_property("summary")
    width       = attr_property("width")

    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
        self._caption = None
        self._tHead   = None
        self._tFoot   = None
        self._rows    = HTMLCollection(doc, list())
        self._tBodies = HTMLCollection(doc, list())

    @property
    def caption(self):
        return self._caption

    @property
    def tHead(self):
        return self._tHead

    @property
    def tFoot(self):
        return self._tFoot

    @property
    def rows(self):
        return self._rows

    @property
    def tBodies(self):
        return self._tBodies

    def createTHead(self):
        if self._tHead:
            return self._tHead

        self._tHead = HTMLTableSectionElement(self.doc, BeautifulSoup.Tag(self.doc, name = 'thead'))
        self.rows.nodes.insert(0, self._tHead)
        return self._tHead

    def deleteTHead(self):
        if self.tHead:
            self._tHead = None
            del self.rows.nodes[0]

    def createTFoot(self):
        if self._tFoot:
            return self._tFoot

        self._tFoot = HTMLTableSectionElement(self.doc, BeautifulSoup.Tag(self.doc, name = 'tfoot'))
        self.rows.nodes.append(self._tFoot)
        return self._tFoot

    def deleteTFoot(self):
        if self._tFoot:
            self._tFoot = None
            del self.rows.nodes[-1]

    def createCaption(self):
        if self._caption:
            return self._caption

        self._caption = HTMLTableCaptionElement(self.doc, BeautifulSoup.Tag(self.doc, name = 'caption'))
        return self._caption

    def deleteCaption(self):
        if self.caption:
            self._caption = None

    # Modified in DOM Level 2
    def insertRow(self, index = None):
        # Insert a new empty row in the table. The new row is inserted immediately before
        # and in the same section as the current indexth row in the table. If index is -1
        # or equal to the number of rows, the new row is appended. In addition, when the
        # table is empty the row is inserted into a TBODY which is created and inserted
        # into the table.

        # `index' specifies the position of the row to insert (starts at 0). The value of
        # -1 can also be used; which result in that the new row will be inserted at the
        # last position. This parameter is required in Firefox and Opera, but optional in
        # Internet Explorer, Chrome and Safari. If this parameter is omitted, insertRow()
        # inserts a new row at the last position in IE and at the first position in Chrome
        # and Safari.
        if index is None:
            if log.ThugOpts.Personality.isIE():
                index = -1
            if log.ThugOpts.Personality.isChrome() or log.ThugOpts.Personality.isSafari():
                index = 0

        row = HTMLTableRowElement(self.doc, BeautifulSoup.Tag(self.doc, name = 'tr'))
        self.rows.nodes.insert(index, row)
        return row

    def deleteRow(self, index):
        if index < -1 or index >= len(self.rows.nodes):
            raise DOMException(DOMException.INDEX_SIZE_ERR)

        del self.rows.nodes[index]

    def appendChild(self, newChild):
        if newChild.tagName.lower() in ('tbody', ):
            self._tBodies.nodes.append(newChild)

        return super(HTMLTableElement, self).appendChild(newChild)

    def removeChild(self, oldChild):
        if oldChild.tagName.lower() in ('tbody', ):
            self._tBodies.nodes.remove(oldChild)

        return super(HTMLTableElement, self).removeChild(oldChild)
