#!/usr/bin/env python

from .Node import Node


class EntityReference(Node):
    def __init__(self, doc, name):
        self.name = name
        Node.__init__(self, doc)

    @property
    def nodeName(self):
        return self.name

    @property
    def nodeType(self):
        return Node.ENTITY_REFERENCE_NODE

    @property
    def nodeValue(self):
        return None
