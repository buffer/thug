#!/usr/bin/env python

from thug.DOM.W3C.Core.DOMException import DOMException
from .HTMLCollection import HTMLCollection


# Introduced in DOM Level 2
class HTMLOptionsCollection(HTMLCollection):
    def __init__(self, doc, nodes):
        HTMLCollection.__init__(self, doc, nodes)

    def getLength(self):
        return len(self.nodes)

    def setLength(self, value):
        raise DOMException(DOMException.NOT_SUPPORTED_ERR)

    length = property(getLength, setLength)

    def namedItem(self, name):
        for key in ('id', 'name', ):
            for node in self.nodes:
                if key in node.tag.attrs and node.tag.attrs[key] in (name, ):
                    return node

        return None
