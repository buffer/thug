#!/usr/bin/env python

from .Node import Node


class ProcessingInstruction(Node):
    def __init__(self, doc, target, tag):
        self._target = target
        self.tag     = tag
        Node.__init__(self, doc)

    @property
    def target(self):
        return self._target

    @property
    def nodeName(self):
        return self._target

    @property
    def nodeType(self):
        return Node.PROCESSING_INSTRUCTION_NODE

    def getNodeValue(self):
        return self.tag

    def setNodeValue(self, value):
        self.data = value

    nodeValue = property(getNodeValue, setNodeValue)
