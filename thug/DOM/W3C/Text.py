#!/usr/bin/env python

from .DOMException import DOMException
from .Node import Node
from .CharacterData import CharacterData


class Text(CharacterData):
    def __repr__(self):
        return "<Text '%s' at 0x%08X>" % (self.tag, id(self))

    def splitText(self, offset):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    def getNodeValue(self):
        return str(self.data)

    def setNodeValue(self, data):
        self.data = data

    nodeValue = property(getNodeValue, setNodeValue)

    @property
    def nodeName(self):
        return "#text"

    @property
    def nodeType(self):
        return Node.TEXT_NODE

    def replaceData(self, offset, count, arg):
        s = self.data[:offset] + arg + self.data[offset + count:]
        self.data = s
        # raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)
