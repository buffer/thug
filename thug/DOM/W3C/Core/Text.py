#!/usr/bin/env python

from .CharacterData import CharacterData
from .DOMException import DOMException


class Text(CharacterData):
    def __init__(self, doc, tag):
        self.data = tag
        CharacterData.__init__(self, doc, tag)

    def splitText(self, offset):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    def getNodeValue(self):
        return str(self.data)

    def setNodeValue(self, value):
        self.data = value

    nodeValue = property(getNodeValue, setNodeValue)

    @property
    def nodeName(self):
        return "#text"

    @property
    def nodeType(self):
        from .Node import Node
        return Node.TEXT_NODE
