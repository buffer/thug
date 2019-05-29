#!/usr/bin/env python

from .Node import Node


class Notation(Node): # pragma: no cover
    @property
    def publicId(self):
        return None

    @property
    def systemId(self):
        return None

    @property
    def nodeName(self):
        pass

    @property
    def nodeType(self):
        return Node.NOTATION_NODE

    @property
    def nodeValue(self):
        return None

    # Introduced in DOM Level 3
    @property
    def textContent(self):
        return None
