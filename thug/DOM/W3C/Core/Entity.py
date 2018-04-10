#!/usr/bin/env python

from .Node import Node


class Entity(Node):
    @property
    def publicId(self):
        pass

    @property
    def systemId(self):
        pass

    @property
    def notationName(self):
        pass

    @property
    def nodeName(self):
        pass

    @property
    def nodeType(self):
        return Node.ENTITY_NODE

    @property
    def nodeValue(self):
        return None
