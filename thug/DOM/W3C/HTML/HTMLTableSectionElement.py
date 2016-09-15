#!/usr/bin/env python

import logging
import bs4 as BeautifulSoup
from thug.DOM.W3C.DOMException import DOMException
from .HTMLElement import HTMLElement
from .HTMLCollection import HTMLCollection
from .HTMLTableRowElement import HTMLTableRowElement
from .attr_property import attr_property

log = logging.getLogger("Thug")


class HTMLTableSectionElement(HTMLElement):
    def __init__(self, doc, tag):
        HTMLElement.__init__(self, doc, tag)
        self._rows = HTMLCollection(doc, list())

    align           = attr_property("align")
    ch              = attr_property("char")
    chOff           = attr_property("charoff")
    vAlign          = attr_property("valign")

    @property
    def rows(self):
        return self._rows

    # Modified in DOM Level 2
    def insertRow(self, index = None):
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

        if index in (-1, len(self._rows), ):
            self.rows.nodes.append(row)
        else:
            self.rows.nodes.insert(index, row)

        return row

    # Modified in DOM Level 2
    def deleteRow(self, index):
        if index < -1 or index >= len(self.rows.nodes):
            raise DOMException(DOMException.INDEX_SIZE_ERR)

        del self.rows.nodes[index]
