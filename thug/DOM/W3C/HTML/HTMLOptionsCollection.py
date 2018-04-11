#!/usr/bin/env python

from thug.DOM.W3C.Core.DOMException import DOMException
from .HTMLCollection import HTMLCollection


# Introduced in DOM Level 2
class HTMLOptionsCollection(HTMLCollection):
    def __init__(self, doc, nodes):
        HTMLCollection.__init__(self, doc, nodes)

    def getLength(self):
        return len(self.nodes)

    def setLength(self):
        raise DOMException(DOMException.NOT_SUPPORTED_ERR)

    length = property(getLength, setLength)
