#!/usr/bin/env python

from .CharacterData import CharacterData


class Comment(CharacterData):
    def __init__(self, doc, tag):
        self.setNodeValue(tag)
        CharacterData.__init__(self, doc, tag)

    @property
    def nodeName(self):
        return "#comment"

    @property
    def nodeType(self):
        from .Node import Node
        return Node.COMMENT_NODE

    def getNodeValue(self):
        return str(self.data)

    def setNodeValue(self, value):
        self._data = value

    nodeValue = property(getNodeValue, setNodeValue)
