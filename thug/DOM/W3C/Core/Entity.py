#!/usr/bin/env python

from .Node import Node


class Entity(Node): # pragma: no cover
    @property
    def publicId(self):
        return None

    @property
    def systemId(self):
        return None

    @property
    def notationName(self):
        return None

    @property
    def nodeName(self):
        return None

    @property
    def nodeType(self):
        return Node.ENTITY_NODE

    @property
    def nodeValue(self):
        return None
