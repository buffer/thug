#!/usr/bin/env python

from .CharacterData import CharacterData


class Comment(CharacterData):
    @property
    def nodeName(self):
        return "#comment"

    @property
    def nodeType(self):
        from .Node import Node
        return Node.COMMENT_NODE

    def getNodeValue(self):
        return self.data

    def setNodeValue(self, value):
        self.data = value

    nodeValue = property(getNodeValue, setNodeValue)
